# استيراد المكتبات المطلوبة  
import base64  
import hashlib  
import secrets  
import time  
import zlib  
import hmac  
import os  
import json  
import sys  
import threading  
from typing import Dict, Any  
from cryptography.hazmat.primitives import hashes, padding  
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  
from cryptography.hazmat.backends import default_backend  

# تعيين عنوان النافذة  
if os.name == 'nt':  # للويندوز  
    os.system('title التشفير فائق السرية')  
else:  # للأنظمة الأخرى  
    print("\033]0;التشفير فائق السرية\007")  

class التشفير_فائق_السرية:  
    def __init__(self, المفتاح_الرئيسي: str):  
        # تطبيع المفتاح الرئيسي  
        self.سلسلة_المفتاح_الرئيسي = str(المفتاح_الرئيسي)  
        
        # تهيئة الأمان متعدد الطبقات  
        self.وقت_التهيئة = time.time()  
        
        # توليد مكونات الأمان  
        self.الملح = self._توليد_الملح_المعقد()  
        
        # استخراج المفتاح الرئيسي  
        self.المفتاح_التناظري = self._استخراج_المفتاح_التناظري()  
        
        # مفتاح HMAC الثابت  
        self.مفتاح_HMAC = self._توليد_مفتاح_HMAC()  
    
    def _توليد_الملح_المعقد(self) -> bytes:  
        """  
        توليد الملح متعدد المكونات ذو الإنتروبيا العالية  
        """  
        return hashlib.sha3_512(  
            self.سلسلة_المفتاح_الرئيسي.encode() +  
            str(self.وقت_التهيئة).encode() +  
            secrets.token_bytes(128)  
        ).digest()  
    
    def _استخراج_المفتاح_التناظري(self) -> bytes:  
        """  
        استخراج المفتاح التناظري متعدد الطبقات بتعقيد متطرف  
        """  
        # المفتاح الأساسي بتكرارات عالية  
        منشئ_المفتاح = PBKDF2HMAC(  
            algorithm=hashes.SHA3_512(),  
            length=32,  # معيار AES-256  
            salt=self.الملح,  
            iterations=10000000  # تكرارات عالية  
        )  
        
        # إدخال مفتاح معقد  
        إدخال_المفتاح = hashlib.sha3_512(  
            self.سلسلة_المفتاح_الرئيسي.encode() +  
            self.الملح +  
            str(self.وقت_التهيئة).encode()  
        ).digest()  
        
        return منشئ_المفتاح.derive(إدخال_المفتاح)  
    
    def _توليد_مفتاح_HMAC(self) -> bytes:  
        """  
        توليد مفتاح HMAC متعدد المكونات بنهج محدد  
        """  
        return hashlib.sha3_512(  
            hashlib.sha3_512(self.سلسلة_المفتاح_الرئيسي.encode()).digest() +  
            self.الملح +  
            hashlib.sha3_512(str(self.وقت_التهيئة).encode()).digest()  
        ).digest()  
    
    def تشفير_فائق(self, البيانات: str) -> Dict[str, Any]:  
        """  
        التشفير متعدد الطبقات مع حماية شاملة  
        """  
        try:  
            # ضغط البيانات  
            بيانات_مضغوطة = zlib.compress(البيانات.encode('utf-8'), level=9)  
            
            # التبطين  
            مبطن = padding.PKCS7(algorithms.AES.block_size).padder()  
            بيانات_مبطنة = مبطن.update(بيانات_مضغوطة) + مبطن.finalize()  
            
            # تشفير AES-256 بوضع GCM  
            متجه_التهيئة = secrets.token_bytes(16)  
            مشفر = Cipher(  
                algorithms.AES(self.المفتاح_التناظري),  
                modes.GCM(متجه_التهيئة),  
                backend=default_backend()  
            )  
            مشفر_التشفير = مشفر.encryptor()  
            
            # تشفير البيانات  
            بيانات_مشفرة = مشفر_التشفير.update(بيانات_مبطنة) + مشفر_التشفير.finalize()  
            علامة = مشفر_التشفير.tag  
            
            # حمولة آمنة للغاية  
            الحمولة = {  
                'التشفير': base64.b85encode(بيانات_مشفرة).decode(),  
                'متجه_التهيئة': base64.b85encode(متجه_التهيئة).decode(),  
                'العلامة': base64.b85encode(علامة).decode(),  
                'الملح': base64.b85encode(self.الملح).decode(),  
                'hmac': base64.b85encode(self.مفتاح_HMAC).decode(),  
                'الطابع_الزمني': self.وقت_التهيئة,  
                'الطول_الأصلي': len(البيانات),  
                'تحقق_السلامة': hashlib.sha3_512(بيانات_مضغوطة).hexdigest(),  
                'إصدار_الخوارزمية': '1.0'  # إضافة إصدار الخوارزمية  
            }  
            
            return الحمولة  
        
        except Exception as e:  
            return {"خطأ": f"فشل التشفير: {str(e)}"}  

    def فك_التشفير_فائق(self, الحمولة: Dict[str, Any], المفتاح_الرئيسي: str) -> str:  
        """  
        فك التشفير متعدد الطبقات مع التحقق الصارم  
        """  
        try:  
            # تطبيع المفتاح الرئيسي  
            سلسلة_المفتاح_الرئيسي = str(المفتاح_الرئيسي)  
            
            # فك ترميز الحمولة  
            بيانات_مشفرة = base64.b85decode(الحمولة['التشفير'])  
            متجه_التهيئة = base64.b85decode(الحمولة['متجه_التهيئة'])  
            العلامة = base64.b85decode(الحمولة['العلامة'])  
            الملح = base64.b85decode(الحمولة['الملح'])  
            
            # إعادة بناء المفتاح بنفس معلمات الحمولة  
            الطابع_الزمني = الحمولة['الطابع_الزمني']  
            
            # استخراج المفتاح مرة أخرى بالملح الأصلي  
            منشئ_المفتاح = PBKDF2HMAC(  
                algorithm=hashes.SHA3_512(),  
                length=32,  
                salt=الملح,  
                iterations=10000000  
            )  
            
            # إدخال مفتاح مطابق للتشفير  
            إدخال_المفتاح = hashlib.sha3_512(  
                سلسلة_المفتاح_الرئيسي.encode() +  
                الملح +  
                str(الطابع_الزمني).encode()  
            ).digest()  
            
            المفتاح_التناظري = منشئ_المفتاح.derive(إدخال_المفتاح)  
            
            # إعادة توليد مفتاح HMAC بنفس الطريقة بالضبط  
            مفتاح_HMAC = hashlib.sha3_512(  
                hashlib.sha3_512(سلسلة_المفتاح_الرئيسي.encode()).digest() +  
                الملح +  
                hashlib.sha3_512(str(الطابع_الزمني).encode()).digest()  
            ).digest()  
            
            # طباعة معلومات التصحيح  
            print("\nمعلومات فك التشفير:")  
            print("المفتاح الرئيسي:", سلسلة_المفتاح_الرئيسي)  
            print("الملح:", base64.b64encode(الملح).decode())  
            print("الطابع الزمني:", الطابع_الزمني)  
            print("توليد HMAC:", base64.b64encode(مفتاح_HMAC).decode())  
            print("HMAC الحمولة:", الحمولة['hmac'])  
            
            # فك تشفير AES-GCM  
            مشفر = Cipher(  
                algorithms.AES(المفتاح_التناظري),  
                modes.GCM(متجه_التهيئة, العلامة),  
                backend=default_backend()  
            )  
            فاك_التشفير = مشفر.decryptor()  
            بيانات_خام = فاك_التشفير.update(بيانات_مشفرة) + فاك_التشفير.finalize()  
            
            # إزالة التبطين  
            مزيل_التبطين = padding.PKCS7(algorithms.AES.block_size).unpadder()  
            بيانات_غير_مبطنة = مزيل_التبطين.update(بيانات_خام) + مزيل_التبطين.finalize()  
            
            # فك الضغط  
            بيانات_مفككة_الضغط = zlib.decompress(بيانات_غير_مبطنة)  
            
            return بيانات_مفككة_الضغط.decode('utf-8')  
        
        except Exception as e:  
            return f"فشل فك التشفير: {str(e)}"  

def إدخال_الحمولة() -> Dict[str, Any]:  
    """  
    وظيفة لإدخال حمولة التشفير بشكل آمن ومرحلي  
    """  
    print("\n--- إدخال حمولة التشفير ---")  
    print("إرشادات الإدخال:")  
    print("1. أدخل الحمولة JSON بشكل كامل")  
    print("2. اضغط Enter مرتين للإنهاء")  
    print("3. تأكد من صحة تنسيق JSON\n")  
    
    سطور_الحمولة = []  
    print("ابدأ إدخال الحمولة (اضغط Enter مرتين للإنهاء):")  
    while True:  
        السطر = input()  
        if السطر == "":  
            # إذا كان Enter فارغًا مرتين، أنهِ الإدخال  
            if len(سطور_الحمولة) > 0:  
                break  
            else:  
                print("لا يمكن أن يكون إدخال الحمولة فارغًا. حاول مرة أخرى.")  
                continue  
        سطور_الحمولة.append(السطر)  
    
    # concatenate payload lines  
    سلسلة_الحمولة = "\n".join(سطور_الحمولة)  
    
    try:  
        # محاولة تحليل JSON  
        الحمولة = json.loads(سلسلة_الحمولة)  
        return الحمولة  
    except json.JSONDecodeError:  
        print("\nخطأ: تنسيق JSON غير صالح!")  
        return None  

def إدخال_رسالة_متعددة_الأسطر() -> str:  
    """  
    وظيفة لإدخال رسالة متعددة الأسطر مع تحديد الإدخال  
    """  
    print("\nأدخل الرسالة (اضغط Enter 4 مرات لإنهاء الإدخال):")  
    سطور_الرسالة = []  
    عداد_إدخال = 0  
    
    while True:  
        السطر = input()  
        
        # إذا كان السطر فارغًا  
        if السطر == "":  
            عداد_إدخال += 1  
            
            # إذا كان قد تم الضغط على Enter 5 مرات (4 مرات فارغة)، أنهِ الإدخال  
            if عداد_إدخال == 3:  
                break  
        else:  
            # إعادة تعيين عداد الإدخال إذا كان هناك إدخال غير فارغ  
            عداد_إدخال = 0  
        
        # أضف السطر إلى القائمة  
        سطور_الرسالة.append(السطر)  
    
    # concatenate message lines  
    الرسالة = "\n".join(سطور_الرسالة)  
    
    return الرسالة  

def حفظ_الرسالة_المفككة():  
    """  
    وظيفة لحفظ الرسالة المفككة في ملف  
    """  
    while True:  
        اسم_الملف = input("أدخل اسم الملف لحفظ الرسالة (مثل: رسالة_سرية.txt): ").strip()  
        
        # التحقق من اسم الملف  
        if not اسم_الملف:  
            print("اسم الملف لا يمكن أن يكون فارغًا!")  
            continue  
        
        try:  
            # تأكد من أن امتداد الملف هو .txt  
            if not اسم_الملف.lower().endswith('.txt'):  
                اسم_الملف += '.txt'  
            
            # حفظ الرسالة في الملف  
            with open(اسم_الملف, 'w', encoding='utf-8') as الملف:  
                الملف.write(الرسالة_المفككة)  
            
            print(f"\nتم حفظ الرسالة بنجاح في {اسم_الملف}")  
            break  
        
        except PermissionError:  
            print("خطأ: ليس لديك إذن للكتابة!")  
        except IOError as خطأ:  
            print(f"فشل حفظ الملف: {خطأ}")  

def البرنامج_الرئيسي():  
    while True:  
        # القائمة الرئيسية  
        print("\n--- التشفير فائق السرية ---")  
        print("1. تشفير رسالة")  
        print("2. فك تشفير رسالة")  
        print("3. الخروج")  
        
        # اختيار المستخدم  
        الاختيار = input("أدخل اختيارك: ").strip()  
        
        if الاختيار == '1':  
            try:  
                # إدخال المفتاح الرئيسي  
                المفتاح_الرئيسي = input("أدخل المفتاح الرئيسي (16 حرفًا على الأقل): ")  
                if len(المفتاح_الرئيسي) < 16:  
                    print("المفتاح قصير جدًا! 16 حرفًا على الأقل.")  
                    continue  
                
                # إدخال رسالة متعددة الأسطر  
                الرسالة = إدخال_رسالة_متعددة_الأسطر()  
                
                # التحقق من الرسالة  
                if not الرسالة.strip():  
                    print("الرسالة لا يمكن أن تكون فارغة!")  
                    continue  
                
                # عرض رسالة المعالجة  
                print("\nجارٍ تشفير الرسالة...")  
                
                # إنشاء كائن التشفير  
                المشفر = التشفير_فائق_السرية(المفتاح_الرئيسي)  
                
                # تشفير الرسالة  
                الحمولة_المشفرة = المشفر.تشفير_فائق(الرسالة)  
                
                # عرض الحمولة المشفرة  
                print("\n--- الحمولة المشفرة ---")  
                سلسلة_الحمولة = json.dumps(الحمولة_المشفرة, indent=2)  
                print(سلسلة_الحمولة)  
                
                # حفظ في ملف اختياري  
                الحفظ = input("\nهل تريد حفظ الحمولة في ملف؟ (نعم/لا): ").lower()  
                if الحفظ == 'نعم':  
                    اسم_الملف = input("أدخل اسم الملف (مثل: رسالة_سرية.json): ")  
                    
                    # رسالة الحفظ  
                    print("\nجارٍ حفظ الحمولة...")  
                    
                    with open(اسم_الملف, 'w') as الملف:  
                        الملف.write(سلسلة_الحمولة)  
                    
                    print(f"تم حفظ الحمولة في {اسم_الملف}")  
            
            except Exception as خطأ:  
                print(f"حدث خطأ: {خطأ}")  
        
        elif الاختيار == '2':  
            try:  
                # اختيار مصدر الحمولة  
                المصدر = input("اختر مصدر الحمولة (1. إدخال يدوي، 2. قراءة من ملف): ")  
                
                if المصدر == '1':  
                    # إدخال الحمولة يدويًا  
                    print("\nالتحقق من الحمولة...")  
                    
                    الحمولة = إدخال_الحمولة()  
                    
                    if الحمولة is None:  
                        continue  
                
                elif المصدر == '2':  
                    # القراءة من ملف  
                    اسم_الملف = input("أدخل اسم ملف الحمولة: ")  
                    
                    # رسالة القراءة  
                    print("\nقراءة ملف الحمولة...")  
                    
                    try:  
                        with open(اسم_الملف, 'r') as الملف:  
                            الحمولة = json.load(الملف)  
                    
                    except FileNotFoundError:  
                        print(f"الملف {اسم_الملف} غير موجود!")  
                        continue  
                    except json.JSONDecodeError:  
                        print(f"تنسيق JSON في {اسم_الملف} غير صالح!")  
                        continue  
                
                else:  
                    print("اختيار غير صالح!")  
                    continue  
                
                # إدخال المفتاح الرئيسي  
                المفتاح_الرئيسي = input("أدخل المفتاح الرئيسي لفك التشفير: ")  
                
                # رسالة فك التشفير  
                print("\nجارٍ فك تشفير الرسالة...")  
                
                # فك تشفير الرسالة  
                المشفر = التشفير_فائق_السرية(المفتاح_الرئيسي)  
                الرسالة_المفككة = المشفر.فك_التشفير_فائق(الحمولة, المفتاح_الرئيسي)  
                
                # عرض النتيجة  
                print("\n--- الرسالة المفككة ---")  
                print(الرسالة_المفككة)  
                
                # خيار حفظ الرسالة  
                while True:  
                    الحفظ = input("\nهل تريد حفظ الرسالة المفككة؟ (نعم/لا): ").lower().strip()  
                    
                    if الحفظ == 'نعم':  
                        # رسالة الحفظ  
                        print("\nجارٍ حفظ الرسالة...")  
                        
                        حفظ_الرسالة_المفككة()  
                        break  
                    elif الحفظ == 'لا':  
                        print("لم يتم حفظ الرسالة.")  
                        break  
                    else:  
                        print("اختيار غير صالح. يرجى إدخال 'نعم' أو 'لا'.")  
            
            except Exception as خطأ:  
                print(f"حدث خطأ أثناء فك التشفير: {خطأ}")   
        
        elif الاختيار == '3':  
            # الخروج من البرنامج  
            print("شكرًا لك. جارٍ الخروج من البرنامج.")  
            break  
        
        else:  
            print("اختيار غير صالح. حاول مرة أخرى.")  

# نقطة دخول البرنامج  
if __name__ == "__main__":  
    البرنامج_الرئيسي()