
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

import java.util.Base64;
import java.util.Scanner;

//import static com.publiccms.common.tools.VerificationUtils.sha1Encode;

public class Main {

    public static final String DEFAULT_CHARSET = "UTF-8";

    public static byte[] base64Decode(String input) {
        return Base64.getDecoder().decode(input);
    }

    public static String decrypt(byte[] input, String key) {
        try {
//            byte[] sha1Key = sha1Encode(key).getBytes(DEFAULT_CHARSET);
            byte[] sha1Key = "2435e960d9be985705455019cfd3bc84c39344db".getBytes("UTF-8");
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
