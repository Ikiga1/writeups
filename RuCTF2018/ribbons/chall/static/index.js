$(document).ready(function () {
    reload_channels();

    $('.btn-subscribe').click(function () {
        $('.modal.subscribe .form').form('clear');
        $('.modal.subscribe').modal('show');
    });

    $('.btn-create').click(function () {
        $('.modal.create .form').form('clear');
        $('.modal.create').modal('show');
    });

    $('.subscribe.form')
        .form({
            fields: {
                invite: 'regExp[/^\\d+:(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/]'
            },
            inline: true,
            onSuccess: async function(e, params) {
                let [id, encodedKey] = params.invite.split(':');
                let key = base64decode(encodedKey);
                let channel = await view(id);
                if (!channel) {
                    alert('Channel not found');
                    $('.subscribe.modal').modal('hide');
                    return;
                }
                localStorageUpdate('subscribed', [], subscribed => {
                    if (!subscribed.find(info => info.id === id))
                        subscribed.push({id, key, name: channel.name});
                    return subscribed;
                });
                location.reload();
            }
        })
        .submit(e => e.preventDefault());


    $('.subscribe.modal')
        .modal({
            onApprove: function () {
                return $('.subscribe.form').form('validate form');
            }
        });

    $('.create.form')
        .form({
            fields: {
                name: ['minLength[3]', 'maxLength[20]'],
                password: ['minLength[8]', 'maxLength[16]']
            },
            inline: true,
            onSuccess: async function (e, params) {
                let id = await add_channel(params.name, params.password);
                if (!id) {
                    alert('Cannot create channel');
                    $('.create.modal').modal('hide');
                    return;
                }
                let key = await get_key(id, params.password);
                if (!key) {
                    alert('Cannot receive channel key');
                    $('.create.modal').modal('hide');
                    return;
                }
                localStorageUpdate('maintained', [], maintained => {
                    maintained.push({id, key, name: params.name});
                    return maintained;
                });
                location.reload();
            }
        })
        .submit(e => e.preventDefault());

    $('.create.modal')
        .modal({
            onApprove: function () {
                return $('.create.form').form('validate form');
            }
        });

    $('.channels .item').click(function () {
        let id = $(this).data('id');
        load_posts(id);
        $('.channels .item').removeClass('active');
        $(this).addClass('active');
        let ownerBlock = $('.owner-block');
        if ($(this).parents('.channels-maintained').length) {
            ownerBlock.show();
            ownerBlock.data('id', id);
        } else {
            ownerBlock.hide();
        }
    });

    $('.item .btn-remove').click(function () {
        let id = $(this).closest('.item').data('id');
        let collectionName = $(this).data('collection');
        localStorageUpdate(collectionName, [], collection => collection.filter(info => info.id !== id));
        location.reload();
    });

    $('.add-post.form')
        .form({
            fields: {
                text: 'empty',
                password: ['minLength[8]', 'maxLength[16]']
            },
            inline: true,
            onSuccess: async function (e, values) {
                let id = $(this).data('id');
                let status = await add_post(id, values.password, values.text);
                switch (status) {
                    case 201:
                        location.reload();
                        break;
                    case 403:
                        alert('Invalid password');
                        break;
                    default:
                        alert('Cannot add post');
                }
            }
        })
        .submit(e => e.preventDefault());

    $('.btn-invite').click(function () {
        let id = $(this).closest('.owner-block').data('id');
        let channel_info = localStorageGet('maintained').find(info => info.id === id);
        let encodedKey = base64encode(restoreArray(channel_info.key));
        $('.invite-text').text(`${channel_info.id}:${encodedKey}`);
        $('.modal.invite').modal('show');
    });

    $('.change-password.form')
        .form({
            fields: {
                password: ['minLength[8]', 'maxLength[16]'],
                new_password: ['minLength[8]', 'maxLength[16]']
            },
            inline: true,
            onSuccess: async function (e, values) {
                let id = $(this).data('id');
                let status = await change_password(id, values.password, values.new_password);
                switch (status) {
                    case 200:
                        alert('Password successfully changed');
                        location.reload();
                        break;
                    case 403:
                        alert('Invalid password');
                        break;
                    default:
                        alert('Password changing failed');
                }
                if (status !== 200) {
                    $('.modal.change-password').modal('hide');
                }
            }
        })
        .submit(e => e.preventDefault());

    $('.change-password.modal')
        .modal({
            onApprove: function () {
                return $('.change-password.form').form('validate form');
            }
        });

    $('.btn-changePassword').click(function () {
        let id = $(this).closest('.owner-block').data('id');
        $('.change-password.form').data('id', id);
        $('.modal.change-password .form').form('clear');
        $('.modal.change-password').modal('show');
    });
});

function append_channels(container, channels) {
    for (let channel of channels) {
        let item = $('<a class="item"></a>');
        container.append(item);
        $(item).text(channel.name);
        $(item).append('<i class="icon link trash alternate outline btn-remove"></i>');
        $(item).data('id', channel.id);
    }
}

function reloadCollection(name) {
    let collection = localStorageGet(name) || [];
    let container = $(`.channels-${name} .channels-list`);
    append_channels(container, collection);
    container.find('.btn-remove').data('collection', name);
}

function reload_channels() {
    reloadCollection('subscribed');
    reloadCollection('maintained');
}

async function load_posts(channel_id) {
    let container = $('.posts-list');
    container.empty();
    let channel_infos = localStorageGet('subscribed') || [];
    channel_infos = channel_infos.concat(localStorageGet('maintained') || []);
    let channel_info = channel_infos.find(info => info.id === channel_id);
    if (!channel_info)
        return;
    let channel = await view(channel_id);
    channel.decrypt(restoreArray(channel_info.key));
    for (let post of channel.posts) {
        let item = $('<div class="ui segment"><pre></pre></div>');
        container.append(item);
        $(item).children('pre').text(post);
    }
    $('.divider').css('visibility', channel.posts.length ? 'visible' : 'hidden');
}

function add_channel(name, password) {
    return fetch("/api/add_channel", postOptions({name, password}))
        .then(response => response.status === 201 ? response.text() : null)
        .then(text => text.split(':')[1])
        .catch(e => {
            console.error(e);
            return false;
        });
}

function add_post(channel_id, password, text) {
    return fetch(`/api/add_post?channel_id=${channel_id}`, postOptions({password, text}))
        .then(response => response.status)
        .catch(e => {
            console.error(e);
            return false;
        });
}

function get_key(channel_id, password) {
    return fetch(`/api/key?channel_id=${channel_id}`, postOptions({password}))
        .then(response => response.status === 200 ? response.arrayBuffer() : null)
        .then(buffer => new Uint8Array(buffer))
        .catch(e => {
            console.error(e);
            return false;
        });
}

function change_password(channel_id, password, new_password) {
    return fetch(`/api/change_password?channel_id=${channel_id}`, postOptions({password, new_password}))
        .then(response => response.status)
        .catch(e => {
            console.error(e);
            return false;
        });
}

function view(channel_id) {
    return fetch(`/api/view?channel_id=${channel_id}`)
        .then(response => response.status === 200 ? response.arrayBuffer() : null)
        .then(buffer => new Channel(buffer))
        .catch(e => {
            console.error(e);
            return false;
        });
}

class Channel {
    constructor(buffer) {
        this._buffer = buffer;
        this._dataview = new DataView(buffer);
        this._position = 0;
        this.name = this._read_str();
        this.posts = [];
        while (this._position < buffer.byteLength) {
            this.posts.push(this._read_buf());
        }
    }

    decrypt(key) {
        this.posts = this.posts.map(post => this._decrypt_post(post, key));
    }

    _decrypt_post(post, key) {
        let resultBytes = [];
        for (let i = 0; i < post.length; i++) {
            resultBytes[i] = post[i] ^ key[i % key.length];
        }
        return this._buf_to_str(new Uint8Array(resultBytes));
    }

    _read_long() {
        let result = this._dataview.getUint32(this._position, true);
        this._position += 8;
        return result;
    }

    _read_buf() {
        let size = this._read_long();
        let result = new Uint8Array(this._buffer, this._position, size);
        this._position += size;
        return result;
    }

    _read_str() {
        return this._buf_to_str(this._read_buf());
    }

    _buf_to_str(buf) {
        return new TextDecoder("utf-8").decode(buf);
    }
}

function querystring(obj) {
    return Object.keys(obj).map(key => `${key}=${encodeURIComponent(obj[key])}`).join('&');
}

function postOptions(bodyData) {
    return {
        method: "POST",
        body: querystring(bodyData),
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        }
    };
}

function base64decode(base64) {
    let raw = atob(base64);
    let rawLength = raw.length;
    let array = new Uint8Array(new ArrayBuffer(rawLength));

    for (i = 0; i < rawLength; i++) {
        array[i] = raw.charCodeAt(i);
    }
    return array;
}

function base64encode(array) {
    return btoa(String.fromCharCode(...array));
}

function restoreArray(obj) {
    return new Uint8Array(Object.assign([], obj));
}

function localStorageUpdate(key, default_value, updater) {
    let current = JSON.parse(localStorage.getItem(key)) || default_value;
    localStorage.setItem(key, JSON.stringify(updater(current)));
}

function localStorageGet(key) {
    return JSON.parse(localStorage.getItem(key) || 'null');
}
