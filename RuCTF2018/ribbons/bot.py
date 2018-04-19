import requests
import random
import string

#Service is running on localhost
TARGET = "127.0.0.1"

BASE_URL = "http://%s:4243/api" %TARGET

def add_channel(name, password):
    url = "%s/add_channel" % (BASE_URL)
    r = requests.post(url, data={'name': name, 'password': password}, stream=True)
    return int(r.raw.read().split(":")[1], 10)

def add_post(channel_id, password, msg):
    url = "%s/add_post?channel_id=%d" % (BASE_URL, channel_id)
    r = requests.post(url, data={'password': password, 'text': msg}, stream=True)
    return r.raw.read()

def gen_string(size):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(size))

def gen_flag(size):
    return ''.join(random.choice(string.letters + string.digits) for _ in range(size)) + '='

for i in range(0,150):
    name = gen_string(5)
    chan_id = add_channel(name,"a"*16)
    password = 'a'*16
    add_post(chan_id, password, "Would you like a flag, wouldn't you? " + gen_string(2))
    add_post(chan_id, password, gen_flag(31))