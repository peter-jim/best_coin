import base64
import os
import time
import json
import hashlib
import binascii
import ecdsa
import dbm
from bson import ObjectId
from flask import Flask, jsonify,request
from uuid import uuid4
from pymongo import MongoClient
db = dbm.open('global_sys_varible', 'c')
db['total_supply'] = str(10000)
total_supply = db['total_supply']
mined = 0
profile_usdt = 0
total_usr = 0
db['pool'] = str('0')
token = 0
db['dot_token_supply_one_hour'] = str(100)
dot_token_supply_one_hour = db['dot_token_supply_one_hour']

all_user_profile=0
'''
满足方程   pool + profile = token
'''
# print(que.get())
# print(que.get())
# print(que.qsize())  #获取队列长度
# print(que.get(timeout=2))


class Blockchain:

  def __init__(self):
    # 下面定义 2 个实例变量
    self.chain = []
    self.current_transactions = []
    # Create the genesis block
    self.new_block(previous_hash=1)

  # 下面定义了一个say实例方法
  def new_block(self,previous_hash=None):
      """
      生成新块
      :param proof: <int> The proof given by the Proof of Work algorithm
      :param previous_hash: (Optional) <str> Hash of previous Block
      :return: <dict> New Block
      """

      block = {
        'index': len(self.chain) + 1,
        'timestamp': time.time(),
        'transactions': self.current_transactions,
        'previous_hash': previous_hash or self.hash(self.chain[-1]),
      }

      # Reset the current list of transactions
      self.current_transactions = []

      self.chain.append(block)
      print("添加block")
      # return self.block


  def new_transaction(self, sender, recipient, amount):
    """
    生成新交易信息，信息将加入到下一个待挖的区块中
    :param sender: <str> Address of the Sender
    :param recipient: <str> Address of the Recipient
    :param amount: <int> Amount
    :return: <int> The index of the Block that will hold this transaction
    """
    self.current_transactions.append({
      'sender': sender,
      'recipient': recipient,
      'amount': amount,
    })

    return self.last_block['index'] + 1

  @property
  def last_block(self):
        return self.chain[-1]

  @staticmethod
  def hash(block):
        """
        生成块的 SHA-256 hash值
        :param block: <dict> Block
        :return: <str>
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

  def get_chain(self):
    for i in self.chain:
      print(i)

  def get_block(self,index):

    print(self.chain[index])

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o,ObjectId):
            return str(o)
        return json.JSONEncoder.default(self,o)



def get_usr_account(address):
    print('获取 account ')
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.account  # 连接account数据库，没有则自动创建
    my_set = db.account
    get_usr_account_result = my_set.find({'_id':address})

    # 查询全部
    for i in get_usr_account_result:
        conn.close()
        return i
        break

def get_quantitative_trading_list():
    '''
    return model list
    '''

    quantitative_trading_list = {

        'dot_spot_one_hour':{
            'apy': 18999,
            'total_pledge':2865785,
            'one_hour_suply':10,
            'usdt_profile':34195819

        },
        'btc_spot_one_hour': {
            'apy': 3528,
            'total_pledge': 9979768,
            'one_hour_suply': 10,
            'usdt_profile': 34195819
        },
        'eth_spot_one_hour': {
            'apy': 48959,
            'total_pledge': 468209,
            'one_hour_suply': 10,
            'usdt_profile': 34195819
        },

    }

    return quantitative_trading_list


def get_all_acount_num():
    print('获取 account 数量')
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.account  # 连接account数据库，没有则自动创建
    my_set = db.account
    get_usr_account_result = my_set.find({})
    sum = 0
    # 查询全部
    for i in get_usr_account_result:
        print(i)
        sum = sum +1
    conn.close()
    print(sum)
    return sum

def get_all_account():
    print('获取 account ')
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.account  # 连接account数据库，没有则自动创建
    my_set = db.account
    get_usr_account_result = my_set.find({})
    # 查询全部
    for i in get_usr_account_result:
        print(i)
    conn.close()

    return get_usr_account_result

def creat_account(address,token,usdt):
    print('创建 账户 account')
    address = address
    token = token
    usdt = usdt
    share = {}
    contract = {
        'nonce':0,
        'usdt':0,
        'dot':0,
        'btc':0
    }
    nonce = 0
    birth_time = time.time()
    hash = hashlib.sha256((address+str(token)+str(usdt)+str(share)+str(contract)+str(nonce)+str(birth_time)).encode()).digest()

    #database mongodb
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.account  # 连接account数据库，没有则自动创建
    my_set = db.account

    my_set.insert_one({'_id': address, 'token': token,'usdt':usdt,
                       'share':share,'contract':contract,'nonce':0,'birth_time':birth_time,'hash':binascii.hexlify(hash).decode()})
    # my_set.update_many({}, {'$rename': {"_id": "address"}})
    # 查询全部
    for i in my_set.find():
        print(i)
    conn.close()

def put_usdt_in_contract(address,usdt):

    print('开始向constract转账')
    # database mongodb
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.account  # 连接account数据库，没有则自动创建
    my_set = db.account
    # 查询全部
    account_usr_base_info = my_set.find_one({'address': address})

    nonce = account_usr_base_info['nonce']
    account_usdt = account_usr_base_info['usdt']
    account_contract = account_usr_base_info['contract']
    conn.close()



    if usdt >= account_usr_base_info['usdt']:
        print('USDT 不足')
        return 'USDT 不足'
    else:

        nonce = nonce + 1
        account_usdt =account_usdt - usdt


        contract = account_usr_base_info['contract']
        contract['usdt'] = contract['usdt'] + usdt
        contract['nonce'] = contract['nonce'] + 1

        account_contract = contract

        conn = MongoClient('127.0.0.1', 27017)
        db = conn.block     #更新数据记录到区块
        my_set = db.block
        my_set.insert_one({'address': address, 'token': account_usr_base_info['token'], 'usdt': account_usr_base_info['usdt']-usdt,
                           'share': account_usr_base_info['share'], 'contract': contract, 'nonce': account_usr_base_info['nonce']+1, 'birth_time': account_usr_base_info['birth_time'],
                           'hash': account_usr_base_info['hash']})
        print(my_set.find_one({'address': address}))
        conn.close()



        #更新原始account 的nonce ，usdt，contract 值

        print('更新原始account 的nonce ，usdt，contract 值')
        # database mongodb
        conn = MongoClient('127.0.0.1', 27017)
        db = conn.account  # 连接account数据库，没有则自动创建
        my_set = db.account
        # update
        my_set.update_one({'address':address},{ '$set':{ 'nonce':nonce,'usdt':account_usdt,'contract':account_contract}})

        print(my_set.find())

        conn.close()
        print('更新成功')
        return '更新成功'

def get_block_by_address(address):

    print('开始获取block')
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.block  # 连接account数据库，没有则自动创建
    my_set = db.block
    get_usr_account_result = my_set.find()

    # 查询全部
    for i in get_usr_account_result:
        print(i)
    conn.close()

    return get_usr_account_result

def delect_all_account(address):
    print('开始删除block')
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.account  # 连接account数据库，没有则自动创建
    my_set = db.account
    my_set.delete_many({})
    conn.close()

def delect_all_block(address):
    print('开始删除block')
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.block  # 连接account数据库，没有则自动创建
    my_set = db.block
    my_set.delete_many({})
    conn.close()

def delect_all_contract(address):
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.contract  # 连接account数据库，没有则自动创建
    my_set = db.contract
    my_set.delete_many({})
    conn.close()
    print('删除contract')

def delect_all_pool(address):
    print('')
    conn = MongoClient('127.0.0.1', 27017)
    pool_db = conn.pool  # 连接contract数据库，没有则自动创建
    pool_set = pool_db.pool
    s=pool_set.delete_many({})
    if pool_set.find({}) == None:
        print('一池 已清空')
    print(s)

def create_smart_contract_session(address,usdt,model):

    print('创建合约任务')
    #检测地址
    conn = MongoClient('127.0.0.1', 27017)
    contract_db = conn.contract  # 连接contract数据库，没有则自动创建
    contract_set = contract_db.contract


    #查找account 账户获取 用户usdt余额
    account_db = conn.account
    account_set = account_db.account
    account_result = account_set.find_one({'_id':address}) #返回查询结果
    usdt=float(usdt)
    if account_result['usdt']>= float(usdt) and float(usdt)  > 0  :

        #插入结果到contract存储位置中
        contract_set.insert_one({
            'nonce':0,
            'address': address,
            'usdt': usdt,
            'model': model,
            'lock': True,
            'dot': 0,
            'btc': 0,
            'eth': 0,
            'time': time.time(),
            'unlock_time': time.time(),
            'profile': None,
            'dot_buy_price': None,
            'eth_buy_price': None,
            'btc_buy_price': None,
            'status':'unprocess'   #unprocess  , processing , finish
        })

        smartcontract_result = contract_set.find() #插入成功
        print('查找插入结果 ',smartcontract_result)
        #更新原数据，account减去相应到usdt
        account_set.update_one({'_id':address},{ '$set':{ 'nonce':account_result['nonce']+1,'usdt':account_result['usdt']-usdt}})
        account_result = account_set.find({'_id': address})
        for i in account_result:
            print('更新account 账户',i)
        conn.close()
        return True
    else:
        print('账户余额不足')
        return False

def get_usr_smartcontract(address):
    # 检测地址
    print("查找合约地址")
    conn = MongoClient('127.0.0.1', 27017)
    contract_db = conn.contract  # 连接contract数据库，没有则自动创建
    contract_set = contract_db.contract
    result =  contract_set.find({'address':address})
    list = []
    for i in result:
        print(i)
        i['_id']=str(i['_id'])
        list.append(i)
    conn.close()
    #print(smartcontract_result)

    return list

def process_dot_spot_one_hour_buy():
    print("dot_spot_one_hour合约地址")
    conn = MongoClient('127.0.0.1', 27017)
    contract_db = conn.contract  # 连接contract数据库，没有则自动创建
    contract_set = contract_db.contract
    dot_spot_one_hour_result = contract_set.find({'model':'dot_spot_one_hour','lock':True,'status':'unprocess'})
    for i in dot_spot_one_hour_result:

        dot_price = get_dot_price()
        dot = i['usdt']/dot_price  # 全部购买dot

        contract_set.update_one({'model':'dot_spot_one_hour','status':'unprocess'},{ '$set':{'dot_buy_price':dot_price ,'nonce':i['nonce']+1,'usdt':0,'dot':dot,'status':'processing'}})

        print(i)

def process_dot_spot_one_hour_sell():
    print('dot_spot_one_hour合约地址 sell')
    conn = MongoClient('127.0.0.1', 27017)
    contract_db = conn.contract  # 连接contract数据库，没有则自动创建
    contract_set = contract_db.contract
    dot_spot_one_hour_result = contract_set.find({'model': 'dot_spot_one_hour', 'lock': True, 'status': 'processing'})
    for i in dot_spot_one_hour_result:
        dot_price = get_dot_price()
        profile = (dot_price-i['dot_buy_price'])*i['dot']#利润
        if profile >= 0 :  # 利润分配 部分 到资金池子
            print('盈利',profile)
            global pool
            pool = profile/2 + pool   # 一半利润加入到池子
            dot_num_sub  =  (profile/2)/dot_price     # 剩余部分折算成dot or usdt  目前策略 dot

            #更新 dot 价格， dot 数量
            contract_set.update_one({'model':'dot_spot_one_hour','status':'processing','_id':i['_id']},{'$set':{'dot_buy_price':dot_price ,'nonce':i['nonce']+1,'usdt':0,'dot':i['dot']-dot_num_sub,'profile':0}})

            print('当前pool有',pool)
        else:     #如果亏损则产生token
            print('亏损',profile)       #这里 有个bug 会更新全部到数据 需要改进
            contract_set.update_one({'model': 'dot_spot_one_hour', 'status': 'processing','_id':i['_id']}, {
                '$set': { 'nonce': i['nonce'] + 1,'profile':profile}}) #只有亏损 才会计入到账户模型
            print(i)

    process_dot_spot_one_hour_token()

def process_dot_spot_one_hour_token():
    '''
    users.find({"age": {"$gt": 20}}) 大于条件查询
    小于collection.find({'_id':{'$lt':ObjectId('51f6126139ecbb1db4a75667')}})
    $gt:大于
    $lt:小于
    $gte:大于或等于
    $lte:小于或等于
    '''

    print('dot_spot_one_hour合约地址 发放代币')
    conn = MongoClient('127.0.0.1', 27017)
    contract_db = conn.contract  # 连接contract数据库，没有则自动创建
    contract_set = contract_db.contract
    dot_spot_one_hour_result = contract_set.find({'status':'processing', 'profile':{'$lt':0}})
    sum = 0
    for i in dot_spot_one_hour_result:
        sum = sum + i['profile']
        print('亏损挖坑权重',sum)   #计算当前状态用户总损失
    #发放token 到 pool
    dot_spot_one_hour_result = contract_set.find({'status': 'processing', 'profile': {'$lt': 0}})
    print('xxx')

    db = dbm.open('global_sys_varible','w')

    for i in  dot_spot_one_hour_result:
        send_token_to_first_pool(address=address,token=(i['profile'])*db['dot_token_supply_one_hour']/sum)

def send_token_to_first_pool(address,token):
    print('发放代币到1池')
    conn = MongoClient('127.0.0.1', 27017)
    pool_db = conn.pool  # 连接contract数据库，没有则自动创建
    pool_set = pool_db.pool
    pool_set.insert_one( {
        'address':address,
        'token':token,
        'time':time.time()})
    conn.close()

def get_first_pool():
    print('查询一池')
    conn = MongoClient('127.0.0.1', 27017)
    pool_db = conn.pool  # 连接contract数据库，没有则自动创建
    pool_set = pool_db.pool
    pool_result = pool_set.find({})
    for i in pool_result:
        print(i)

def second_pool():
    pass

def get_dot_price():
    return 20

def generate_ECDSA_keys():
    """This function takes care of creating your private and public (your address) keys.
    It's very important you don't lose any of them or those wallets will be lost
    forever. If someone else get access to your private key, you risk losing your coins.

    private_key: str
    public_ley: base64 (to make it shorter)
    """
    sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1) #this is your sign (private key)
    private_key = sk.to_string().hex() #convert your private key to hex
    vk = sk.get_verifying_key() #this is your verification key (public key)
    public_key = vk.to_string().hex()
    print('private_key',private_key)
    print('public_key',public_key)
    #we are going to encode the public key to make it shorter
    public_key = base64.b64encode(bytes.fromhex(public_key))
    print('base64',public_key)



    # filename = input("Write the name of your new address: ") + ".txt"
    # with open(filename, "w") as f:
    #     f.write("Private key: {0}\nWallet address / Public key: {1}".format(private_key, public_key.decode()))
    # print("Your new address and private key are now in the file {0}".format(filename))

def ecdsa_test(seed):
    '''
    它还包括使用的256位曲线 比特币，简称secp256k1 . https://vimsky.com/zh-tw/examples/detail/python-method-ecdsa.SECP256k1.html
    '''
    # # secexp=ecdsa.util.randrange_from_seed__trytryagain(seed,ecdsa.NIST256p)
    # return ecdsa.SigningKey.from_secret_exponent(secexp, curve=ecdsa.NIST256p)

def sign_ECDSA_msg(private_key,message):
    """Sign the message to be sent
    private_key: must be hex
    return
    signature: base64 (to make it shorter)
    message: str
    """
    # Get timestamp, round it, make it into a string and encode it to bytes
    message = str(message)
    bmessage = message.encode()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=ecdsa.SECP256k1)
    # print(len(sk.sign(bmessage)))
    # signature = base64.b64encode(sk.sign(bmessage))
    signature=sk.sign(bmessage)
    return signature, message

def vertify_ECDSA_msg(public_key,message,signature):
    '''
    public_key: str
    message: str

    return
    ture or false
    '''
    vt = ecdsa.VerifyingKey.from_string(binascii.unhexlify(public_key), curve=ecdsa.SECP256k1)
    print(vt.verify(signature=signature, data=message.encode()))

def mongo_test():

    '''
    https://blog.csdn.net/weixin_43632687/article/details/104201185 高级操作
    #match用户筛选,相当于sql语句中的where后面的表达式
match = {}
match['date'] = {
   '$gte' : '2015-08-21',   #大于等于2015年8月21日的
   '$lte' : '2015-08-23'    #小于等于2015年8月23日的
}

    result.count() 可以计算结果是否为空 ，有多少个数据
    '''
    print('mongo db test ')
    conn = MongoClient('127.0.0.1', 27017)
    db = conn.account  # 连接account数据库，没有则自动创建
    my_set = db.account
    match = {}
    match['token'] = {
        '$lt': 2030
    }

    # get_usr_account_result = my_set.aggregate([{"$project":{"token":1,"contract":1}}])
    my_set.update_many({}, {'$rename': {"_id": "a"}})
    # for i in get_usr_account_result:
    #     print(i)

def encryption_transferr_test():

    A_private = 'a224f7960645bbbf12f56ea85fd3803472f5b248f09a38980fc5b32e1ddcee03'
    A_public = 'e7451f21592f90e05bcd05921fb34c0547b73d43a0387d15df58b244bb3d5cfa3bda61ed5b527c936e5276f25092e8cd953fec4c3e53e73ba30578d8dafda8cd'
    A_address = 'e7451f21592f90e05bd05921fb34c0547b73d43a0387d15df58b244bb3d5cfa3bda61ed5b527c936e5276f25092e8cd953fec4c3e53e73ba30578d8dafda8cd'

    B_private = '060618f01667c0f6f2d1a73deb7970ba471bdefd38f58e09817d7c3b8d335583'
    B_public = '3070eeb27fab9f10581d71f97aa20d1861b1695cb6d3bb839fcbdee9a8020359d8671cf26359bac3ecb32d4c16aeacb718b4ff80e1659063a0a9ec16116f9bef'
    B_address = 'MHDusn+rnxBYHXH5eqINGGGxaVy207uDn8ve6agCA1nYZxzyY1m6w+yzLUwWrqy3GLT/gOFlkGOgqewWEW+b7w=='

    #A向B 转账100元
    info = A_address + '&' + B_address +'&'+str(100)
    info = info.encode()
    #生成摘要
    digest = hashlib.sha256(info).hexdigest()
    print(digest)
    #生成数字签名 记录A的合法性
    signature, message=sign_ECDSA_msg(A_private,digest)   #signature 是byte字节









def web_Flask():
    # Instantiate our Node
    app = Flask(__name__)
    # Generate a globally unique address for this node
    node_identifier = str(uuid4()).replace('-', '')
    # Instantiate the Blockchain
    blockchain = Blockchain()
    @app.route('/mine', methods=['GET'])
    def mine():
        return "We'll mine a new Block"

    @app.route('/transactions/new', methods=['POST'])
    def new_transaction():
        return "We'll add a new transaction"

    @app.route('/chain', methods=['GET'])
    def full_chain():
        response = {
            'chain': blockchain.chain,
            'length': len(blockchain.chain),
        }
        return jsonify(response), 200

    @app.route('/get/sys',methods=['GET'])
    def get_sys_base_info():
        #获取系统当前的基本信息
        response = {
            'total_supply':total_supply.decode(),
            'mined':mined,
            'profile_usdt':profile_usdt,
            'total_user':get_all_acount_num()
        }
        return jsonify(response), 200

    @app.route('/get/account', methods=['PUT','GET'])
    def get_address_info():
        # 获取系统当前的基本信息
        if request.method == 'POST':
            address = request.form('address')
            print(address)

        else:
            print('get')
            address = request.args.get('address')
            get_usr_account_result = get_usr_account(address)

            response = {
                'address':get_usr_account_result['_id'],
                'token':get_usr_account_result['token'],
                'usdt':get_usr_account_result['usdt'],
                'share':get_usr_account_result['share'],
                'contract':get_usr_account_result['contract'],
                'nonce':get_usr_account_result['nonce'],
                'birth_time':get_usr_account_result['birth_time'],
                'hash':get_usr_account_result['hash']
            }
            print(type(response))
            return jsonify(response), 200

    @app.route('/get/quantitative/model/list', methods=['PUT', 'GET'])
    def get_trading_list():
        'return model list of quantitative model list'
        if request.method == 'POST':
            return '还没开发'

        else:
            return jsonify(get_quantitative_trading_list())

    @app.route('/get/contract', methods=['PUT', 'GET'])
    def get_contract():
        if request.method == 'POST':
            return '还没开发'

        else:
            address = request.args.get('address')
            result = get_usr_smartcontract(address)
            return jsonify(result)

    @app.route('/send/quantitative', methods=['PUT', 'GET'])
    def send_quantitative_tcontract():
        '''
        this function is to slove quantitative model to contract.usr's address will send to server contract
        and contract will process
        request:model nane such as 'dot_spot_one_hour' btc_spot_one_hour' eth_spot_one_hour'
        response:False True
        '''
        if request.method == 'POST':
            return '还没开发'

        else:
            address = request.args.get('address')
            usdt = request.args.get('usdt')
            model = request.args.get('model')
            result_of_creat_session=create_smart_contract_session(address, usdt, model)

            print(result_of_creat_session)


            return '成功'




    return app



if __name__ == '__main__':

    address = '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM'
    #mainChian = Blockchain()
    # creat_account('12UwLL9Risc3QfPqBUvKofHmBQ7wMtjv4',1000,89000)
    # delect_all_block(address)
    # delect_all_account(address)
    # delect_all_contract(address)
    # delect_all_pool(address)

    # app = web_Flask()
    # app.run(host='0.0.0.0', port=5000)

    encryption_transferr_test()


    # get_all_account()
    # get_all_acount_num(address)

    # database mongodb

    # create_smart_contract_session('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjv1', 300,'spot')
    # create_smart_contract_session('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjv2', 300, 'spot')
    # create_smart_contract_session('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjv3', 300, 'spot')
    # create_smart_contract_session('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjv4', 300, 'spot')

    # get_usr_account(address)
    # mongo_test()
    # get_usr_account(address)
    #
    #put_usdt_in_contract(address,500)

    #get_block_by_address(address)
    # create_smart_contract_session(address,100,'spot')
    # process_dot_spot_one_hour_buy()

    get_usr_smartcontract('12UwLL9Risc3QfPqBUvKofHmBQ7wMtjv4')
    #process_dot_spot_one_hour_token()
    # get_all_account()

    # process_dot_spot_one_hour_sell()
    # generate_ECDSA_keys()
    # private_key = 'ef6bcc28dbdb4c9987544066b9cbfb40cbedf45502c40a4571c917b476cf6449'
    # public_key = '42ac4d4c0a0d0de6d5125c8fa0532729e984afd2984c782428fe7dd535c1190b0447f8233e9b9ad8c29754c20694d71e059f3eedb2025abe4c9cefeb9f66a4d6'
    # signature, message=sign_ECDSA_msg(private_key,'hello')
    # vertify_ECDSA_msg(public_key,message)



    # get_usr_smartcontract(address)
    #
    #
    # get_first_pool()
    #app.run(host='0.0.0.0', port=5000)

    # mainChian = Blockchain()
    # mainChian.new_transaction(1,2,100)
    # mainChian.new_transaction(1,3,100)
    # mainChian.new_transaction(1,4,100)
    # mainChian.new_block(22)
    # mainChian.get_chain()
    # mainChian.get_block(0)