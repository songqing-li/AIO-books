# -*- coding:utf-8 -*-
import os
import qrcode
from PIL import Image
from pyzbar import pyzbar

#QrCode编码
def makeQrCode(content, save_path=None):
    qr_code_maker = qrcode.QRCode(version=5,
                                  error_correction=qrcode.constants.ERROR_CORRECT_M,
                                  box_size=8,
                                  border=4,
                                  )
    qr_code_maker.add_data(data=content)
    qr_code_maker.make(fit=True)
    img = qr_code_maker.make_image(fill_color="black", back_color="white")
    img.save(save_path)
    #img.show()
    """
    #中间图不显示
    if save_path:
        img.save(save_path)
    else:
        img.show()
    """

#QrCode解码
def decodeQrCode(code_img_path):
    if not os.path.exists(code_img_path):
        raise FileExistsError(code_img_path)

    # Here, set only recognize QR Code and ignore other type of code
    return pyzbar.decode(Image.open(code_img_path), symbols=[pyzbar.ZBarSymbol.QRCODE])

'''
if __name__ == "__main__":
    img_save_path = r'D:\Diploma_project\QRCode\qrcode.png'
    print("============QRcodetest===============")
    print("         1、Make a QRcode            ")
    print("         2、Scan a QRcode            ")
    print("=====================================")
    print("1.请输入编码信息：")
    codeData = input('>>:').strip()
    makeQrCode(codeData, img_save_path)
    print("正在编码：")
    results = decodeQrCode("qrcode.png")
    print("2.正在解码：")
    if len(results):
        print("解码结果是：")
        print(results[0].data.decode("utf-8"))
    else:
        print("Can not recognize.")
'''