package jp.truetech.experiment.crypto;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.util.Base64;

import javax.crypto.SecretKey;

import org.junit.Test;

public class KeyLoaderTest {

    private String privateKeyB64 =
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDMUeL4xY8lJawF"
          + "MVyNWev7cbqMWqq1d8piylaZrhAM3iukn+UXXApWxgDA97O2RiSoRvZXMckmGpuG"
          + "WBfeJDbyaNQ9oNxIEzwG27JC9e38f2a7Z/mqM7S9GJCOR6me62TQBpFH2f4hlX4O"
          + "FEhHN1ld0buMM1Ns/f9e5wmS/i+ZNcXClR65idaLfimjpHxzc2WUeoBCz48wD6Fx"
          + "pUIMZJB9wZPz/VmYbOcXAk4kuBFdbWvoiGUtYhJAgMABs/0uBTtIeURJNMheoQhF"
          + "+o6JoqN20byv+RUWuMznHlO2BBQBtEbFwSp+T8i2zhBcUaP1yDaZS3wIvEJsY8lo"
          + "gD4LFTL3AgMBAAECggEAQJwUXf57CZAkGXBGiBxLVzPbfc6d9Mxwn1TElcxJHwiS"
          + "XHiDhSOB0XbDfkHV/mmn5d6qv1/q77WyQIVS5tgk1/r2Qpa/kbsjXDfU4v/JxfKz"
          + "lceHV58KJFHERHm81ZgyROYOwt3YUt5nAiS/xmVmSRitaeRBGVIokuYUTPs8KgIa"
          + "YZwIF1/HcC6lq1lIKfdlkATvxxKIqFfjHXC2lEQkDX17yqamLbmN1QAqrVc3yaah"
          + "CdhcXR7FYmdFCIvWD4BsZm2NF0j7a5DkohVCGuG9Nu6RzkuxHlQtGs4tQsAKsNqw"
          + "Vr742mMTIDvYpeaQItm4Uf8/5YY9P464edzVh3jyIQKBgQDob4LrFQyaPxvGuW7Q"
          + "+gYHTM/t9q3doNFDWV5WdI/NHABxhEZiaL+O8t1bLk+zUjDZG9gUkzZ0fj2hu8Zk"
          + "vG0V54im4KvCy+k5Y0z6sCF2heml33kItqZl8fb1MuWbri1AhkSw2bzONojiy5VQ"
          + "1d/xMc6yaxs2pGDm7Kt/qfGDywKBgQDhCK1hs4MIBY1Z8mAewpxdP+C6kUdl02ys"
          + "Mp2JvyEAPIdbW0cWjswVZ4REePp2cT254MgnOgbSwz4JLULY4l6h6MwBzUJhLMdS"
          + "InHWQbcIXk5P37NLjCF6yL3stNwxEGjrDdYcu5nHUclw8NmzA7hNj4QTuR/zDa59"
          + "YYcs6KTgBQKBgB3NZnjj6wi//Ly/O/E5jZpUA/kb/vEC1LIQ/GKTcXi4FWp4rlmh"
          + "2qXmh/FP/9IbQL4lrs/8jCflo9tf6zExY79CP6g9+Gfyo0XDcLRX7wJ2ax3kiG1Q"
          + "lgdOPf70drI+Y/j4/ke6s1Wxcl26ArwpoBwZ6cnAp+2ap/4T7G1jCd9/AoGBAN6y"
          + "D6MYWxudIv1Ydvb58HP3uxXmn5mNWYYvsOeYVbg+LlWiRv9z4VNtVd/NOU/tUQCa"
          + "CnmHWylIPiQmvniTzMK99uXxkzdHcRk/LRizf8awTR+OaYjh7F/uOMX/VcjYTHwQ"
          + "/UsB/HTb41X5g/c8Py/CTxqVoaCOcZdy5Kr0r/VhAoGAARA3KIOcMKmnayXSw2Wl"
          + "t+UAC0G3hwfGuhrddELs0pMYzs68TmX57tG7VdquO1FqbzUDnr2qHKRvszvwA1ZW"
          + "CS4lFDHmj94WYHB3oKqs7fiyCEsG3v2bJ3+vi3141cNdjTEBOOP4IZXXdOI3N1ai"
          + "Wvg3R9L7CXx7R+8MQ1D4UDc=";
    private String wrappedKeyB64 =
            "KgWZkhryvOA9cXwhJSwI0UPiPc1ITzD3A6Q1pljpDYlWJO/zPMvUxdkrYKMIfUAi"
          + "e20IIzpyenXB+ARI1zM4u3vL9RB2UEHnSXY9cZy6SrhaY0SYYhHL5x1wzWOlru/0"
          + "9WdRJwKIN4/pyOQ4Atetj4W5fch5WhZJQu8mUL3hQAkucHkIrV2uE9IDB1R7NO1w"
          + "K0OrMM7oh4Is1xwRK2KT0HXyCyLQg3kW5zHF7hm45T2NkFECDtqzZkNA+GlsR9rl"
          + "lpkd6GQuYTvTkKa/YnfXedx/B3BMaq8wfQwJ9y5flQqVYB4ilkNYt+HAbpDgi+hN"
          + "owzBZzHPXKBzPATzOegpCw==";

    @Test
    public void load() throws Exception {
        byte[] privateKey = Base64.getDecoder().decode(privateKeyB64);
        byte[] wrappedKey = Base64.getDecoder().decode(wrappedKeyB64);
        SecretKey secretKey = new KeyLoader().loadSecretKey(privateKey, wrappedKey);
        Crypto.setSecretKey(secretKey);

        String ivB64 = "2k/I0KZNPl4+3ySkfRtHxg==";
        String plain = "Hello";

        String encryptedB64 = "gOOy6WfnpPFq0mRurrHe/Q==";
        String decrypted = new String(Crypto.decrypt(
                Base64.getDecoder().decode(encryptedB64), 
                Base64.getDecoder().decode(ivB64)));
        System.out.println(decrypted);
        assertThat(decrypted, is(plain));
    }
}
