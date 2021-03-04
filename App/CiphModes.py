from hpc import generate_hpc_functions
from PyQt5.QtWidgets import QProgressBar


def ECB_encrypt(ptxt: list, key: str, spice: int, progress: QProgressBar = None) -> list:
    """ ptxt: list of blocks 
    (each block is str (hex integer))
        key: hex_str

        return list of encrypted block
    """

    encrypt = generate_hpc_functions(key, (len(ptxt[0]) - 2) * 4, (len(key) - 2) * 4)[0]

    res = []
    if progress:  # progress bar используется
        value = 100 / len(ptxt)
        checkValue = value
        for elem in ptxt:
            res.append(encrypt(elem, spice))
            if checkValue > 1:
                progress.setValue(progress.value() + int(checkValue))
                checkValue = value
            else:
                checkValue += value

        progress.setValue(100)
    else:
        for elem in ptxt:
            res.append(encrypt(elem, spice))

    ###
    print(res)
    ###

    return res


def ECB_decrypt(ctxt: list, key: str, spice: int, progress: QProgressBar = None) -> list:
    decrypt = generate_hpc_functions(key, (len(ctxt[0]) - 2) * 4, (len(key) - 2) * 4)[1]

    res = []
    if progress:  # progress bar используется
        value = 100 / len(ctxt)
        checkValue = value
        for elem in ctxt:
            res.append(decrypt(elem, spice))
            if checkValue > 1:
                progress.setValue(progress.value() + int(checkValue))
                checkValue = value
            else:
                checkValue += value

        progress.setValue(100)
    else:
        for elem in ctxt:
            res.append(decrypt(elem, spice))

    ###
    print(res)
    ###

    return res


def CBC_encrypt(ptxt: list, key: str, spice: int, iv: str = None, progress: QProgressBar = None) -> list:
    """ iv: hex str """

    # для xor с первым блоком нужен одинаковый размер блока и вектора
    if iv:
        if len(ptxt[0]) != len(iv):
            raise ValueError('text size != init vector size')

    encrypt = generate_hpc_functions(key, (len(ptxt[0]) - 2) * 4, (len(key) - 2) * 4)[0]

    if iv:
        ptxt[0] = encrypt(xor(ptxt[0], iv), spice)
    else:
        ptxt[0] = encrypt(ptxt[0], spice)

    if progress:
        value = 100 / len(ptxt)
        checkValue = value
        for i in range(1, len(ptxt)):
            ptxt[i] = encrypt(xor(ptxt[i], ptxt[i - 1]), spice)
            if checkValue > 1:
                progress.setValue(progress.value() + int(checkValue))
                checkValue = value
            else:
                checkValue += value

        progress.setValue(100)
    else:
        for i in range(1, len(ptxt)):
            ptxt[i] = encrypt(xor(ptxt[i], ptxt[i - 1]), spice)

    ###
    print(ptxt)
    ###

    return ptxt


def CBC_decrypt(ctxt: list, key: str, spice: int, iv: str = None, progress: QProgressBar = None) -> list:
    # для xor с первым блоком нужен одинаковый размер блока и вектора
    if iv:
        if len(ctxt[0]) != len(iv):
            raise ValueError('text size != init vector size')

    decrypt = generate_hpc_functions(key, (len(ctxt[0]) - 2) * 4, (len(key) - 2) * 4)[1]

    if progress:
        value = 100 / len(ctxt)
        checkValue = value
        for i in reversed(range(1, len(ctxt))):
            ctxt[i] = (xor(decrypt(ctxt[i], spice), ctxt[i - 1]))
            if checkValue > 1:
                progress.setValue(progress.value() + int(checkValue))
                checkValue = value
            else:
                checkValue += value
    else:
        for i in reversed(range(1, len(ctxt))):
            ctxt[i] = (xor(decrypt(ctxt[i], spice), ctxt[i - 1]))

    if iv:
        ctxt[0] = xor(decrypt(ctxt[0], spice), iv)
    else:
        ctxt[0] = decrypt(ctxt[0], spice)

    if progress:
        progress.setValue(100)

    ###
    print(ctxt)
    ###

    return ctxt


def CFB_encrypt(ptxt: list, key: str, spice: int, iv: str, progress: QProgressBar = None) -> list:
    # для xor с первым блоком нужен одинаковый размер блока и вектора
    if len(ptxt[0]) != len(iv):
        raise ValueError('text size != init vector size')

    encrypt = generate_hpc_functions(key, (len(ptxt[0]) - 2) * 4, (len(key) - 2) * 4)[0]

    iv = encrypt(iv, spice)
    ptxt[0] = xor(ptxt[0], iv)

    if progress:
        value = 100 / len(ptxt)
        checkvalue = value
        for i in range(1, len(ptxt)):
            ptxt[i] = xor(encrypt(ptxt[i - 1], spice), ptxt[i])
            if checkvalue > 1:
                progress.setValue(progress.value() + int(checkvalue))
                checkvalue = value
            else:
                checkvalue += value

        progress.setValue(100)
    else:
        for i in range(1, len(ptxt)):
            ptxt[i] = xor(encrypt(ptxt[i - 1], spice), ptxt[i])

    ###
    print(ptxt)
    ###

    return ptxt


def CFB_decrypt(ctxt: list, key: str, spice: int, iv: str, progress: QProgressBar = None) -> list:
    if len(ctxt[0]) != len(iv):
        raise ValueError('text size != init vector size')

    encrypt = generate_hpc_functions(key, (len(ctxt[0]) - 2) * 4, (len(key) - 2) * 4)[0]

    if progress:
        value = 100 / len(ctxt)
        checkValue = value
        for i in reversed(range(1, len(ctxt))):
            ctxt[i] = (xor(encrypt(ctxt[i - 1], spice), ctxt[i]))
            if checkValue > 1:
                progress.setValue(progress.value() + checkValue)
                checkValue = value
            else:
                checkValue += value
    else:
        for i in reversed(range(1, len(ctxt))):
            ctxt[i] = (xor(encrypt(ctxt[i - 1], spice), ctxt[i]))

    if iv:
        ctxt[0] = xor(encrypt(iv, spice), ctxt[0])

    if progress:
        progress.setValue(100)

    ###
    print(ctxt)
    ###

    return ctxt


def OFB_encrypt(ptxt: list, key: str, spice: int, iv: str, progress: QProgressBar = None) -> list:
    # для xor с первым блоком нужен одинаковый размер блока и вектора
    if len(ptxt[0]) != len(iv):
        raise ValueError('text size != init vector size')

    encrypt = generate_hpc_functions(key, (len(ptxt[0]) - 2) * 4, (len(key) - 2) * 4)[0]

    if progress:
        value = 100 / len(ptxt)
        checkValue = value
        for i in range(0, len(ptxt)):
            iv = encrypt(iv, spice)
            ptxt[i] = xor(iv, ptxt[i])
            if checkValue > 1:
                progress.setValue(progress.value() + int(checkValue))
                checkValue = value
            else:
                checkValue += value

        progress.setValue(100)
    else:
        for i in range(0, len(ptxt)):
            iv = encrypt(iv, spice)
            ptxt[i] = xor(iv, ptxt[i])

    ###
    print(ptxt)
    ###

    return ptxt


def OFB_decrypt(ctxt: list, key: str, spice: int, iv: str, progress: QProgressBar = None) -> list:
    return OFB_encrypt(ctxt, key, spice, iv, progress)


def xor(left: str, right: str) -> str:
    """get to str (hex integer), xor them 
    and return result str
    """

    if len(left) != len(right):
        raise ValueError('xor error')

    length = len(left) - 2  # не считаем 0x...
    res = hex(int(left, 16) ^ int(right, 16))[2:]

    # нужно сохранить длину hex строки, после операции xor
    return '0x' + '0' * (length - len(res)) + res
