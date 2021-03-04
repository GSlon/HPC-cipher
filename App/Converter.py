class Converter():
    @staticmethod
    def bytes_to_hex_list(data: bytes, blocksize: int, useLastBlock=True) -> list:
        """ return list of blocks 
        useLastBlock дописывает последний блок,
        где будет хранится количество значимых 
        цифр предпоследнего
        """

        ###
        print('bytes', data)
        ###

        res = []

        byteCount = blocksize // 8
        for i in range(len(data)//byteCount):
            block = '0x'
            for elem in data[i*byteCount:(i+1)*byteCount]:   # elem is byte
                if len(hex(elem)) == 3: 
                    block += ('0' + hex(elem)[2:])                
                else:
                    block += hex(elem)[2:]
            res.append(block)

        if not useLastBlock:
            return res

        # последний блок, который меньше blocksize
        # при чтении зашифрованного файла такого блока не будет
        if (len(data) % byteCount) != 0:
            block = '0x'
            for elem in data[(len(data)//byteCount)*byteCount:]:   # elem is byte
                if len(hex(elem)) == 3:
                    block += ('0' + hex(elem)[2:])                
                else:
                    block += hex(elem)[2:]

            lastBlckSize = len(block)-2
            # дополняем последний блок до длины blocksize
            # дополнение через 1 не теряет цифры в алгоритме, в отличие от 0 
            block = '0x' + block[2:] + '1' * (byteCount - lastBlckSize // 2) * 2
            res.append(block)   

            # добавляем последний блок, который будет содержать 
            # число значимых цифр предыдущего блока
            # вид: 0xf0011111... -> 15 значащих цифр
            hstrLstBlckSize = '0x'
            if len(hex(lastBlckSize)) == 3:
                hstrLstBlckSize += ('0' + hex(lastBlckSize)[2:])                
            else:
                hstrLstBlckSize += hex(lastBlckSize)[2:]
            
            lastBlock = '0x' + hstrLstBlckSize[2:] + '00' + '1'*(byteCount-1 - len(hstrLstBlckSize[2:])//2)*2   
            res.append(lastBlock)
        else:
            # если дополнять до block size не надо, то последний блок 
            # содержит только единицы
            lastBlock = '0x' + '1'*byteCount*2
            res.append(lastBlock)

        return res     

    @staticmethod
    def hex_to_bytes(blocks: list, useLastBlock=True) -> bytes:
        """
            get list of blocks (each block is hex_str)
            return in bytes
        """

        ###
        print('get in')
        ###

        res = []
        for block in blocks[:-2]:
            clrBlock = block[2:]
            for i in range(len(clrBlock)//2):
                res.append(int('0x' + clrBlock[i*2:(i+1)*2], 16).to_bytes(1, byteorder='big'))

        if not useLastBlock:
            for block in blocks[-2:]:   # оставшиеся два блока
                clrBlock = block[2:] 
                for i in range(len(clrBlock)//2):
                    res.append(int('0x' + clrBlock[i*2:(i+1)*2], 16).to_bytes(1, byteorder='big'))
            return b''.join(res)

        # если последний блок не состоит из одних
        # единиц, то надо парсить предпоследний блок 
        if blocks[-1:][0].find('00') != -1:
            # последний блок содержит число значимых цифр в предпоследнем
            block = blocks[-1:][0]
            num = int(block[: block.find('00')], 16) 

            # преобразуем последний блок 'полезных данных'
            block = blocks[-2:-1][0][2:num+2]  # блок исходных данных без добавок до blocksize  
            for i in range(len(block)//2):
                res.append(int('0x' + block[i*2:(i+1)*2], 16).to_bytes(1, byteorder='big')) 
        else:
            block = blocks[-2:-1][0][2:]  
            for i in range(len(block)//2):
                res.append(int('0x' + block[i*2:(i+1)*2], 16).to_bytes(1, byteorder='big')) 

        ###
        print('bytes', res)
        ###

        return b''.join(res)
