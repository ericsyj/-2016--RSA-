import gmpy2
import binascii

def find_same_n(ns):  # 寻找求出模n一样的帧的编号
    temp = []
    for i in range(len(ns)):
        if(i in temp):
            continue
        same = [i]
        for j in range(i+1, len(ns)):
            if(ns[j] == ns[i]):
                same.append(j)
                temp.append(j)
        if(len(same) > 1):
            print(same)


def find_same_factor(ns):  # 寻找出模n有公因子的帧的编号
    for i in range(len(ns)):
        same = [i]
        for j in range(i+1, len(ns)):
            if ns[j] != ns[i]:
                fac = gmpy2.gcd(int(ns[j], 16), int(ns[i], 16))
                if fac > 1:
                    same.append(j)
                    same.append(fac)
                    if(len(same) > 1):
                        print(same)


def same_modulus_attack(index1, index2):  # 共模攻击，已知index1，index2分别为0,4
    e1 = int(es[index1], 16)
    e2 = int(es[index2], 16)
    n = int(ns[index1], 16)
    c1 = int(cs[index1], 16)
    c2 = int(cs[index2], 16)
    s = gmpy2.gcdext(e1, e2)
    s1 = s[1]
    s2 = s[2]
    # 求模反元素
    if s1 < 0:
        s1 = - s1
        c1 = gmpy2.invert(c1, n)
    elif s2 < 0:
        s2 = - s2
        c2 = gmpy2.invert(c2, n)
    m = pow(c1, s1, n)*pow(c2, s2, n) % n
    print(binascii.a2b_hex(hex(m)[-16:]).decode())
    result = binascii.a2b_hex(hex(m)[-16:]).decode()
    return result


def same_factor_attack():  # 因数碰撞攻击
    plaintext = []
    index = [1, 18]
    p_of_frame = gmpy2.gcd(int(ns[index[0]], 16), int(ns[index[1]], 16))
    q_of_frame1 = int(ns[index[0]], 16) // p_of_frame
    q_of_frame18 = int(ns[index[1]], 16) // p_of_frame
    phi_of_frame1 = (p_of_frame-1)*(q_of_frame1-1)
    phi_of_frame18 = (p_of_frame-1)*(q_of_frame18-1)
    d_of_frame1 = gmpy2.invert(int(es[index[0]], 16), phi_of_frame1)
    d_of_frame18 = gmpy2.invert(int(es[index[1]], 16), phi_of_frame18)
    plaintext_of_frame1 = gmpy2.powmod(
        int(cs[index[0]], 16), d_of_frame1, int(ns[index[0]], 16))
    plaintext_of_frame18 = gmpy2.powmod(
        int(cs[index[1]], 16), d_of_frame18, int(ns[index[1]], 16))
    final_plain_of_frame1 = binascii.a2b_hex(
        hex(plaintext_of_frame1)[-16:]).decode()
    final_plain_of_frame18 = binascii.a2b_hex(
        hex(plaintext_of_frame18)[-16:]).decode()
    plaintext.append(final_plain_of_frame1)
    plaintext.append(final_plain_of_frame18)
    print(plaintext[0])
    print(plaintext[1])
    return plaintext


def chinese_remainder_theorem(items):  # 中国剩余定理
    N = 1
    for a, n in items:
        N *= n
        result = 0
    for a, n in items:
        m = N//n
        d, r, s = gmpy2.gcdext(n, m)
        if d != 1:
            N = N//n
            continue
        result += a*s*m
    return result % N, N


def low_e_3():  # 对Frame7,11,15低加密指数广播攻击e == 3
    sessions = [{"c": int(cs[7], 16), "n": int(ns[7], 16)},
                {"c": int(cs[11], 16), "n":int(ns[11], 16)},
                {"c": int(cs[15], 16), "n":int(ns[15], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开三次方根
    plaintext7_11_15 = gmpy2.iroot(gmpy2.mpz(x), 3)
    return binascii.a2b_hex(hex(plaintext7_11_15[0])[-16:])


def low_e_5():  # 对Frame3,8,12,16,20低加密指数广播攻击e == 5
    sessions = [{"c": int(cs[3], 16), "n": int(ns[3], 16)},
                {"c": int(cs[8], 16), "n":int(ns[8], 16)},
                {"c": int(cs[12], 16), "n":int(ns[12], 16)},
                {"c": int(cs[16], 16), "n":int(ns[16], 16)},
                {"c": int(cs[20], 16), "n":int(ns[20], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开五次方根
    plaintext3_8_12_16_20 = gmpy2.iroot(gmpy2.mpz(x), 5)
    return binascii.a2b_hex(hex(plaintext3_8_12_16_20[0])[-16:]).decode()


def low_e_3_f7_f11():   # 对Frame7,11低加密指数广播攻击e == 3
    sessions = [{"c": int(cs[7], 16), "n": int(ns[7], 16)},
                {"c": int(cs[11], 16), "n":int(ns[11], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开三次方根
    plaintext7_11_15 = gmpy2.iroot(gmpy2.mpz(x), 3)
    return binascii.a2b_hex(hex(plaintext7_11_15[0])[-16:])


def low_e_3_f7_f15():  # 对Frame7,15低加密指数广播攻击e == 3
    sessions = [{"c": int(cs[7], 16), "n": int(ns[7], 16)},
                {"c": int(cs[15], 16), "n":int(ns[15], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开三次方根
    plaintext7_11_15 = gmpy2.iroot(gmpy2.mpz(x), 3)
    return binascii.a2b_hex(hex(plaintext7_11_15[0])[-16:])


def low_e_3_f11_f15():  # 对Frame11,15低加密指数广播攻击e == 3
    sessions = [{"c": int(cs[11], 16), "n":int(ns[11], 16)},
                {"c": int(cs[15], 16), "n":int(ns[15], 16)}]
    data = []
    for session in sessions:
        data = data+[(session['c'], session['n'])]
    x, y = chinese_remainder_theorem(data)
    # 直接开三次方根
    plaintext7_11_15 = gmpy2.iroot(gmpy2.mpz(x), 3)
    return binascii.a2b_hex(hex(plaintext7_11_15[0])[-16:])


def pq(n):  # 费马分解
    u = 0
    v = 0
    i = 0
    u0 = gmpy2.iroot(n, 2)[0]+1
    while(1):
        u = (u0+i)**2-n
        if gmpy2.is_square(u):
            v = gmpy2.isqrt(u)
            return u0+i+v
        i += 1


def get_content_of_frame10_14():  # 对Frame10,14进行解密
    list = [10, 14]
    for i in list:
        p = pq(int(ns[i], 16))
        n = int(ns[i], 16)
        c = int(cs[i], 16)
        e = int(es[i], 16)
        q = n // p
        phi_of_frame10 = (p-1)*(q-1)
        d = gmpy2.invert(e, phi_of_frame10)
        m = gmpy2.powmod(c, d, n)
        final_plain = binascii.a2b_hex(hex(m)[-16:]).decode()
        print(final_plain)


def pp1(n):  # 假定p-1的每个素因子小于B,尝试分解n
    B = gmpy2.mpz(2**20)
    a = 2
    for i in range(2, B+1):
        a = pow(a, i, n)
    p = gmpy2.gcd(a-1, n)
    if p < n and p > 1:
        return p
    else:
        return 0


def pollard_resolve():  # 对Frame2,6,19解密
    index_list = [2, 6, 19]
    plaintext = []
    for i in index_list:
        N = int(ns[i], 16)
        c = int(cs[i], 16)
        e = int(es[i], 16)
        p = pp1(N)
        if p == 0:
            print("frame%d cracking failed" % (i))
            return
        print("p of frame " + str(i) + " is : " + str(p))
        q = N // p
        phi_of_frame = (p-1)*(q-1)
        d = gmpy2.invert(e, phi_of_frame)
        m = gmpy2.powmod(c, d, N)
        plaintext.append(binascii.a2b_hex(hex(m)[-16:]).decode())
        print(binascii.a2b_hex(hex(m)[-16:]).decode())
    return plaintext

if __name__ == "__main__":
    ns = []
    es = []
    cs = []
    for i in range(21):
        with open(r"C:\Users\67475\Desktop\RSA加密体制破译题目\密码挑战赛赛题三\附件3-2（发布截获数据）\Frame"+str(i), "r") as f:
            Framei = f.read()
            ns.append(Framei[0:256])
            es.append(Framei[256:512])
            cs.append(Framei[512:768])

    # find_same_n(ns)
    # find_same_factor(ns)
    '''
    for i in range(21):
        print('Frame' + str(i))
        print('N = ' + str(ns[i]))
        print('E = ' + str(es[i]))
        print('C = ' + str(cs[i]))
    '''
    # 对Frame0和Frame4共模攻击
    # same_modulus_attack(0,4)

    # 对Frame1和Frame18进行因数碰撞攻击
    # same_factor_attack()

    # 对Frame7,11,15低加密指数广播攻击e == 3
    # print(low_e_3())
    # 对Frame3,8,12,16,20低加密指数广播攻击e == 5
    # print(low_e_5())
    # 对Frame7,11,15低加密指数广播攻击e == 3两两爆破
    '''
    print(low_e_3_f7_f11())
    print(low_e_3_f7_f15())
    print(low_e_3_f11_f15())
    '''
    # 尝试费马分解
    # fermat_resolve()
    # 发现对Frame10,14分解有效，故对其解密
    # get_content_of_frame10_14()

    # 发现对Frame2,6,19可以进行Pollard p-1分解
    # pollard_resolve()
