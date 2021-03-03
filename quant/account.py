import json
import pymongo
from pymongo import MongoClient


class account():

    address = []
    pub_key= []
    token = []
    share = []
    contract = []
    nonce = 0
    time = 0
    storage = []
    hash = []


    def __init__(self):
        self.address='16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM'
        self.pub_key='0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6'
        self.token=20000
        self.nonce=0
        self.contract = {
            'usdt':0,
            'token':0,
            'dot':0,
            'eth':0,
            'btc':0,
            'link':0,
            'cnonce':0
        }
        self.share = []


    def coinbase(self,address,private_key,num):
        self.token = self.token + num
        self.nonce = self.nonce + 1


    def contract_pool(self,get_asset_value):
        print(self.contract)

    def save_account_json(self):
        conn = MongoClient('127.0.0.1', 27017)
        db = conn.account  # 连接account数据库，没有则自动创建
        my_set = db.test_set

        print('l连接成功，开始插入')

        my_set.insert_one({"address": "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM" })
        # 查询全部
        for i in my_set.find():
            print(i)


        account = {
            'address':self.address,
            'pub_key':self.pub_key,
            'token':self.token,
            'share':self.share,
            'contract':self.contract,
            'nonce':self.nonce
        }
        account = json.dumps(account)
        print(account)

    def add_share_friends(self):
        self.share.append('sdada')
        print(self.share)

    def send_token_to_address(self):
        #检查发送地址合法性，检查接收地址合法性，检查地址余额
        pass

    def send_token_to_contract(self):
        pass

    def get_contract_token(self):
        pass

    def withdraw_contract_token(self):
        pass

    def contract_token_process_with_day(self):
        pass

    def contract_token_process_with_one_hours(self):
        pass

    def create_account(self,token_usdt,address,share_by_address=None):
        self.token = token_usdt
        self.address = address
        self.share.append(share_by_address)





a =account()
a.add_share_friends()
print(a.coinbase('aaa','vbbb',3))
print(a.token)
print(a.contract_pool(10))
print(a.save_account_json())











