//
//  mac_patch_helper_test.m
//  mac_patch_helper_test
//
//  Created by 马治武 on 2024/5/4.
//

#import <XCTest/XCTest.h>
#import "encryp_utils.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>

@interface encryp_test : XCTestCase

@end

@implementation encryp_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}



- (void) test_tablepls_deviceid {
    
    NSString *deviceId = [EncryptionUtils generateTablePlusDeviceId];
    // 默认    11:33:13.548069+0800    TablePlus    >>>>>> deviceId: ee4f1d1890b4eb49a5a4d7f195ca8b67
    NSLog(@"deviceId :%@",deviceId);
    
}

- (void) test_ccc_encryp {
    
    
    //  自定义你字符串加密
    //  NSString *message = @"Hello, CCCrypt!";
    //  NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    
    //  自定义 char 数组加密
    unsigned char charArray[] = {1, 10, 100, 200};
    NSUInteger length = sizeof(charArray) / sizeof(unsigned char); // 计算数组长度
    NSMutableData *data = [NSMutableData data];
    [data appendBytes:charArray length:length];
    
    
    // 加密
    // PKpqMB5NRTTrK2nyiDcg7ZXlN3TmMI2q9vBLq48So+Y=
    //    NSData *key = [@"0123456789012345" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key = [[NSData alloc] initWithBase64EncodedString:@"PKpqMB5NRTTrK2nyiDcg7ZXlN3TmMI2q9vBLq48So+Y=" options:0];
    
    // leU3dOYwjar28EurjxKj5g==
    //    NSData *iv = [@"abcdefghijklmnop" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *iv = [[NSData alloc] initWithBase64EncodedString:@"leU3dOYwjar28EurjxKj5g==" options:0];
    
    NSData *encryptedData = [EncryptionUtils cccEncryptData:data withKey:key iv:iv];
    NSString *encryptedDataBase64 = [encryptedData base64EncodedStringWithOptions:0];
    NSLog(@"encryptedDataBase64: %@", encryptedDataBase64); // 5HxqsB1DW2UPHea90LJ4mA==
    
    // e2RBDmVbZz/y4IusF2ZNlw==
    //    NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:@"e2RBDmVbZz/y4IusF2ZNlw==" options:0];
    
    if (encryptedData) {
        NSLog(@"Encrypted data: %@", encryptedData);
        // 解密
        NSData *decryptedData = [EncryptionUtils cccDecryptData:encryptedData withKey:key iv:iv];
        
        if (decryptedData) {
            NSString *decryptedMessage = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            NSLog(@"Decrypted message: %@", decryptedMessage);
        } else {
            NSLog(@"Decryption failed.");
        }
    } else {
        NSLog(@"Encryption failed.");
    }
    
    
    
}
- (void)test_surge_device{
    NSString *deviceId = [EncryptionUtils generateSurgeDeviceId];
    NSLog(@"deviceId -> %@",deviceId);
    
}
- (void)test_rsa_encyp {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
    // 生成公钥私钥
    bool is_pkcs8 = true;
    NSDictionary * keys = [EncryptionUtils generateKeyPair:is_pkcs8];
    NSString *publicKeyStr = [keys objectForKeyedSubscript:@"publicKey"];
    NSString *privateKeyStr = [keys objectForKeyedSubscript:@"privateKey"];
    NSLog(@"publicKeyStr: %@",publicKeyStr);
    NSLog(@"privateKeyStr: %@",privateKeyStr);
    
    
    // 2025-05-04T09:22:47Z
    NSDictionary *jsonLicense = @{
        @"deviceID": @"16b8f4bdfd55d29f737427b4ec0c14d7",
        @"type":@"licensed", // trial:licensed:revoked
        @"product": @"SURGEMAC5",
        @"expiresOnDate": @1746350567,
        // @"p": @"e2RBDmVbZz/y4IusF2ZNlw==",
        @"p": @"xkIQAJe6FhgdEh3Q1y7+Sg=="
    };
    
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:jsonLicense options:NSJSONWritingPrettyPrinted error:nil];
    NSString *text = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    
    NSString *textBase64 = [[text dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
    
    NSLog(@"textBase64 :%@",textBase64);
    
    // sign
    NSData *sign = [EncryptionUtils generateSignatureForData:[text dataUsingEncoding:NSUTF8StringEncoding] privateKey:privateKeyStr isPKCS8:is_pkcs8];
    NSString *signBase64 = [sign base64EncodedStringWithOptions:0];
    
    // sign vefify
    NSLog(@"signBase64: %@",signBase64);
    Boolean verify = [EncryptionUtils verifySignatureWithBase64:textBase64 signature:signBase64 publicKey:publicKeyStr isPKCS8:is_pkcs8];
    NSLog(@"verify: %hhu",verify);
    
    NSString *test = @"123";
    // rsa 加密
    NSData* enData = [EncryptionUtils rsaEncryptData:[test dataUsingEncoding:NSUTF8StringEncoding] withPublicKey:publicKeyStr isPKCS8:is_pkcs8];
    NSLog(@"enData : %@",enData);
    // rsa 解密
    NSData* deData = [EncryptionUtils rsaDecryptData:enData withPrivateKey:privateKeyStr isPKCS8:is_pkcs8];
    NSLog(@"deData : %@",deData);
}

- (void)test_jvsm_encode {
    
    
    NSString* deviceId = @"16b8f4bdfd55d29f737427b4ec0c14d7";
    NSString *deviceIdSha256  = [EncryptionUtils sha256Hash:[deviceId dataUsingEncoding:NSUTF8StringEncoding]];
    NSRange range = NSMakeRange(32, 32);
    NSString *deviceIdSha256Sub = [deviceIdSha256 substringWithRange:range];
    NSLog(@"deviceIdSha256: %@",deviceIdSha256);
    NSLog(@"deviceIdSha256Sub: %@",deviceIdSha256Sub);
    
    
    NSData *key = [EncryptionUtils hexStringToBytes:deviceIdSha256];
    NSData *iv = [EncryptionUtils hexStringToBytes:deviceIdSha256Sub];
    
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:@"IWZ1bmN0aW9uKCl7ZnVuY3Rpb24gZShlKXtmb3IodmFyIHM9d2luZG93LmF0b2IoZSksbj1zLmxlbmd0aCx0PW5ldyBVaW50OEFycmF5KG4pLG89MDtvPG47bysrKXRbb109cy5jaGFyQ29kZUF0KG8pO3JldHVybiB0fWZ1bmN0aW9uIHMoZSl7cmV0dXJuIEFycmF5QnVmZmVyLmlzVmlldyhlKSYmIShlIGluc3RhbmNlb2YgRGF0YVZpZXcpfWZ1bmN0aW9uIG4oZSl7Zm9yKHZhciBzLG4sdCxvLGkscj0iIix1PSJBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvIixkPW5ldyBVaW50OEFycmF5KGUpLGE9ZC5ieXRlTGVuZ3RoLGw9YSUzLGY9YS1sLGM9MDtjPGY7Yys9MylzPSgxNjUxNTA3MiYoaT1kW2NdPDwxNnxkW2MrMV08PDh8ZFtjKzJdKSk+PjE4LG49KDI1ODA0OCZpKT4+MTIsdD0oNDAzMiZpKT4+NixyKz11W3NdK3Vbbl0rdVt0XSt1W289NjMmaV07cmV0dXJuIDE9PWw/KHM9KDI1MiYoaT1kW2ZdKSk+PjIscis9dVtzXSt1W249KDMmaSk8PDRdKyI9PSIpOjI9PWwmJihzPSg2NDUxMiYoaT1kW2ZdPDw4fGRbZisxXSkpPj4xMCxuPSgxMDA4JmkpPj40LHIrPXVbc10rdVtuXSt1W3Q9KDE1JmkpPDwyXSsiPSIpLHJ9ZnVuY3Rpb24gdChlKXtyZXR1cm4ic3RyaW5nIj09dHlwZW9mIGV8fGUgaW5zdGFuY2VvZiBTdHJpbmd9ZnVuY3Rpb24gbyhlKXtyZXR1cm4ib2JqZWN0Ij09dHlwZW9mIGUmJm51bGwhPT1lfWZ1bmN0aW9uIGkoZSl7aWYoIm9iamVjdCIhPXR5cGVvZiBlfHxudWxsPT09ZXx8cyhlKSlyZXR1cm4gZTtsZXQgbj1BcnJheS5pc0FycmF5KGUpP1tdOnt9O2ZvcihsZXQgdCBpbiBlKXtsZXQgbz1lW3RdOyJmdW5jdGlvbiIhPXR5cGVvZiBvJiYoblt0XT1pKG8pKX1yZXR1cm4gbn1mdW5jdGlvbiByKHIsdSxkKXtsZXQgYTtpZihvKHUpKXtpZigoYT1pKHUpKS5ib2R5JiZzKGEuYm9keSkpe2xldCBsPW4oYS5ib2R5KTtkZWxldGUgYS5ib2R5LGEuX19yYXdCb2R5PWx9fWVsc2UgaWYodCh1KSlhPXU7ZWxzZXtkKCJJbnZhbGlkIHBhcmFtZXRlciIsbnVsbCxudWxsKTtyZXR1cm59d2luZG93LndlYmtpdC5tZXNzYWdlSGFuZGxlcnMuYWJyaWRnZS5wb3N0TWVzc2FnZSh7bWV0aG9kOiIkaHR0cENsaWVudCIscGF5bG9hZDp7cDphLEhUVFBNZXRob2Q6cn19KS50aGVuKHM9Pnt2YXIgbj1udWxsO3MuYm9keT9uPXMuYm9keTpzLl9fcmF3Qm9keSYmKG49ZShzLl9fcmF3Qm9keSkpLGQocy5lcnJvcixzLnJlc3BvbnNlLG4pfSkuY2F0Y2goZT0+e2NvbnNvbGUubG9nKGUpfSl9aWYod2luZG93Lm9uZXJyb3I9ZnVuY3Rpb24oZSxzLG4sdCxvKXtyZXR1cm4gd2luZG93LndlYmtpdC5tZXNzYWdlSGFuZGxlcnMuc2JyaWRnZS5wb3N0TWVzc2FnZSh7bWV0aG9kOiJlcnJvciIscGF5bG9hZDp7bWVzc2FnZTplLHNvdXJjZTpzLGxpbmVubzpuLGNvbG5vOnQsZXJyb3I6b319KSwhMH0sZ2xvYmFsVGhpcy5jb25zb2xlLmxvZz1mdW5jdGlvbihlKXsic3RyaW5nIiE9dHlwZW9mIGUmJihlPUpTT04uc3RyaW5naWZ5KGUpKSx3aW5kb3cud2Via2l0Lm1lc3NhZ2VIYW5kbGVycy5zYnJpZGdlLnBvc3RNZXNzYWdlKHttZXRob2Q6ImNvbnNvbGUubG9nIixwYXlsb2FkOntjb250ZW50OmV9fSl9LGdsb2JhbFRoaXMuJGRvbmU9ZnVuY3Rpb24oZSl7aWYobyhlPWkoZSkpKXtpZihlLmJvZHkmJnMoZS5ib2R5KSl7bGV0IHQ9bihlLmJvZHkpO2RlbGV0ZSBlLmJvZHksZS5fX3Jhd0JvZHk9dH1pZihvKGUucmVzcG9uc2UpJiZlLnJlc3BvbnNlLmJvZHkmJnMoZS5yZXNwb25zZS5ib2R5KSl7bGV0IHI9bigocmVzcG9uc2U9ey4uLmUucmVzcG9uc2V9KS5ib2R5KTtkZWxldGUgcmVzcG9uc2UuYm9keSxyZXNwb25zZS5fX3Jhd0JvZHk9cixlLnJlc3BvbnNlPXJlc3BvbnNlfX13aW5kb3cud2Via2l0Lm1lc3NhZ2VIYW5kbGVycy5zYnJpZGdlLnBvc3RNZXNzYWdlKHttZXRob2Q6IiRkb25lIixwYXlsb2FkOmUsdmVyOiIyMDI0MDIyNDA1NzQzMzc4In0pfSxnbG9iYWxUaGlzLiRwZXJzaXN0ZW50U3RvcmU9e3dyaXRlOmZ1bmN0aW9uKGUscyl7cmV0dXJuIHQoZSl8fG51bGw9PT1lfHwoZT1KU09OLnN0cmluZ2lmeShlKSksInN1Y2Nlc3MiPT09cHJvbXB0KEpTT04uc3RyaW5naWZ5KHttZXRob2Q6IiRwZXJzaXN0ZW50U3RvcmUud3JpdGUiLGNvbnRlbnQ6ZSxrZXk6cyxzZXNzaW9uOiRzY3JpcHQuc2Vzc2lvbklEfSkpfSxyZWFkOmZ1bmN0aW9uKGUpe3JldHVybiBwcm9tcHQoSlNPTi5zdHJpbmdpZnkoe21ldGhvZDoiJHBlcnNpc3RlbnRTdG9yZS5yZWFkIixrZXk6ZSxzZXNzaW9uOiRzY3JpcHQuc2Vzc2lvbklEfSkpfX0sZ2xvYmFsVGhpcy4kbm90aWZpY2F0aW9uPXtwb3N0OmZ1bmN0aW9uKGUscyxuLHQpe3dpbmRvdy53ZWJraXQubWVzc2FnZUhhbmRsZXJzLnNicmlkZ2UucG9zdE1lc3NhZ2Uoe21ldGhvZDoiJG5vdGlmaWNhdGlvbi5wb3N0IixwYXlsb2FkOnt0aXRsZTplLHN1YnRpdGxlOnMsYm9keTpuLGluZm86dH19KX19LGdsb2JhbFRoaXMuJGh0dHBDbGllbnQ9e2dldDpmdW5jdGlvbihlLHMpe3IoIkdFVCIsZSxzKX0scG9zdDpmdW5jdGlvbihlLHMpe3IoIlBPU1QiLGUscyl9LHB1dDpmdW5jdGlvbihlLHMpe3IoIlBVVCIsZSxzKX0sZGVsZXRlOmZ1bmN0aW9uKGUscyl7cigiREVMRVRFIixlLHMpfSxoZWFkOmZ1bmN0aW9uKGUscyl7cigiSEVBRCIsZSxzKX0sb3B0aW9uczpmdW5jdGlvbihlLHMpe3IoIk9QVElPTlMiLGUscyl9LHBhdGNoOmZ1bmN0aW9uKGUscyl7cigiUEFUQ0giLGUscyl9fSxnbG9iYWxUaGlzLiRodHRwQVBJPWZ1bmN0aW9uIGUocyxuLHQsbyl7d2luZG93LndlYmtpdC5tZXNzYWdlSGFuZGxlcnMuYWJyaWRnZS5wb3N0TWVzc2FnZSh7bWV0aG9kOiIkaHR0cEFQSSIscGF5bG9hZDp7bWV0aG9kOnMscGF0aDpuLGJvZHk6dH19KS50aGVuKGU9PntvKGUpfSkuY2F0Y2goZT0+e2NvbnNvbGUubG9nKGUpfSl9LGdsb2JhbFRoaXMuJHV0aWxzPXtnZW9pcDpmdW5jdGlvbihlKXtyZXR1cm4gcHJvbXB0KEpTT04uc3RyaW5naWZ5KHttZXRob2Q6IiR1dGlscy5nZW9pcCIsc2Vzc2lvbjokc2NyaXB0LnNlc3Npb25JRCxhZGRyZXNzOmV9KSl9LGlwYXNuOmZ1bmN0aW9uKGUpe3JldHVybiBwcm9tcHQoSlNPTi5zdHJpbmdpZnkoe21ldGhvZDoiJHV0aWxzLmlwYXNuIixzZXNzaW9uOiRzY3JpcHQuc2Vzc2lvbklELGFkZHJlc3M6ZX0pKX0saXBhc286ZnVuY3Rpb24oZSl7cmV0dXJuIHByb21wdChKU09OLnN0cmluZ2lmeSh7bWV0aG9kOiIkdXRpbHMuaXBhc28iLHNlc3Npb246JHNjcmlwdC5zZXNzaW9uSUQsYWRkcmVzczplfSkpfSx1bmd6aXA6ZnVuY3Rpb24odCl7aWYoIXModCkpcmV0dXJuIG51bGw7dmFyIG89cHJvbXB0KEpTT04uc3RyaW5naWZ5KHttZXRob2Q6IiR1dGlscy51bmd6aXAiLHNlc3Npb246JHNjcmlwdC5zZXNzaW9uSUQsX19yYXdEYXRhOm4odCl9KSk7cmV0dXJuIG8/ZShvKTpudWxsfX0sZ2xvYmFsVGhpcy4kc3VyZ2U9e3NldFNlbGVjdEdyb3VwUG9saWN5OmZ1bmN0aW9uKGUscyl7cmV0dXJuInN1Y2Nlc3MiPT09cHJvbXB0KEpTT04uc3RyaW5naWZ5KHttZXRob2Q6IiRzdXJnZS5zZXRTZWxlY3RHcm91cFBvbGljeSIsc2Vzc2lvbjokc2NyaXB0LnNlc3Npb25JRCxncm91cE5hbWU6ZSxwb2xpY3lOYW1lOnN9KSl9LHNlbGVjdEdyb3VwRGV0YWlsczpmdW5jdGlvbigpe3JldHVybiBKU09OLnBhcnNlKHByb21wdChKU09OLnN0cmluZ2lmeSh7bWV0aG9kOiIkc3VyZ2Uuc2VsZWN0R3JvdXBEZXRhaWxzIixzZXNzaW9uOiRzY3JpcHQuc2Vzc2lvbklEfSkpKX0sc2V0T3V0Ym91bmRNb2RlOmZ1bmN0aW9uKGUpe3JldHVybiJzdWNjZXNzIj09PXByb21wdChKU09OLnN0cmluZ2lmeSh7bWV0aG9kOiIkc3VyZ2Uuc2V0T3V0Ym91bmRNb2RlIixzZXNzaW9uOiRzY3JpcHQuc2Vzc2lvbklELGRlc2lyZWRNb2RlOmV9KSl9LHNldEhUVFBDYXB0dXJlRW5hYmxlZDpmdW5jdGlvbihlKXtyZXR1cm4ic3VjY2VzcyI9PT1wcm9tcHQoSlNPTi5zdHJpbmdpZnkoe21ldGhvZDoiJHN1cmdlLnNldEhUVFBDYXB0dXJlRW5hYmxlZCIsc2Vzc2lvbjokc2NyaXB0LnNlc3Npb25JRCxvbjohIWV9KSl9LHNldENlbGx1bGFyTW9kZUVuYWJsZWQ6ZnVuY3Rpb24oZSl7cmV0dXJuInN1Y2Nlc3MiPT09cHJvbXB0KEpTT04uc3RyaW5naWZ5KHttZXRob2Q6IiRzdXJnZS5zZXRDZWxsdWxhck1vZGVFbmFibGVkIixzZXNzaW9uOiRzY3JpcHQuc2Vzc2lvbklELG9uOiEhZX0pKX0sc2V0UmV3cml0ZUVuYWJsZWQ6ZnVuY3Rpb24oZSl7cmV0dXJuInN1Y2Nlc3MiPT09cHJvbXB0KEpTT04uc3RyaW5naWZ5KHttZXRob2Q6IiRzdXJnZS5zZXRSZXdyaXRlRW5hYmxlZCIsc2Vzc2lvbjokc2NyaXB0LnNlc3Npb25JRCxvbjohIWV9KSl9LHNldEVuaGFuY2VkTW9kZUVuYWJsZWQ6ZnVuY3Rpb24oZSl7cmV0dXJuInN1Y2Nlc3MiPT09cHJvbXB0KEpTT04uc3RyaW5naWZ5KHttZXRob2Q6IiRzdXJnZS5zZXRFbmhhbmNlZE1vZGVFbmFibGVkIixzZXNzaW9uOiRzY3JpcHQuc2Vzc2lvbklELG9uOiEhZX0pKX0scmV0ZXN0R3JvdXA6ZnVuY3Rpb24oZSxzKXtyZXR1cm4gd2luZG93LndlYmtpdC5tZXNzYWdlSGFuZGxlcnMuYWJyaWRnZS5wb3N0TWVzc2FnZSh7bWV0aG9kOiIkc3VyZ2UucmV0ZXN0R3JvdXAiLHBheWxvYWQ6e2dyb3VwTmFtZTplfX0pLnRoZW4oZT0+e3MoZSl9KSwhMH19LCJ1bmRlZmluZWQiIT10eXBlb2YgJHJlcXVlc3QmJiRyZXF1ZXN0JiYkcmVxdWVzdC5fX3Jhd0JvZHkpe2xldCB1PWUoJHJlcXVlc3QuX19yYXdCb2R5KTtkZWxldGUgJHJlcXVlc3QuX19yYXdCb2R5LCRyZXF1ZXN0LmJvZHk9dX1pZigidW5kZWZpbmVkIiE9dHlwZW9mICRyZXNwb25zZSYmJHJlc3BvbnNlJiYkcmVzcG9uc2UuX19yYXdCb2R5KXtsZXQgZD1lKCRyZXNwb25zZS5fX3Jhd0JvZHkpO2RlbGV0ZSAkcmVzcG9uc2UuX19yYXdCb2R5LCRyZXNwb25zZS5ib2R5PWR9fSgpOw==" options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    
    NSData *encryptedData = [EncryptionUtils cccEncryptData:data withKey:key iv:iv];
    NSString *encryptedDataBase64 = [encryptedData base64EncodedStringWithOptions:0];
    NSLog(@"encryptedDataBase64: %@", encryptedDataBase64); // 5HxqsB1DW2UPHea90LJ4mA==

    
    
}
- (void)test_jvsm_decode {
    
    NSString* deviceId = @"16b8f4bdfd55d29f737427b4ec0c14d7";
    NSString *deviceIdSha256  = [EncryptionUtils sha256Hash:[deviceId dataUsingEncoding:NSUTF8StringEncoding]];
    NSRange range = NSMakeRange(32, 32);
    NSString *deviceIdSha256Sub = [deviceIdSha256 substringWithRange:range];
    NSLog(@"deviceIdSha256: %@",deviceIdSha256);
    NSLog(@"deviceIdSha256Sub: %@",deviceIdSha256Sub);
    
    
    NSData *key = [EncryptionUtils hexStringToBytes:deviceIdSha256];
    NSData *iv = [EncryptionUtils hexStringToBytes:deviceIdSha256Sub];

    NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:@"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" options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    
    NSData *decryptedData = [EncryptionUtils cccDecryptData:encryptedData withKey:key iv:iv];

    
    if (decryptedData) {
        
        NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
        
        NSLog(@"Decrypted message %@",decryptedString);
    } else {
        NSLog(@"Decryption failed.");
    }

    

}
- (void)test_rsa_encyp_final {
    
    
    NSString* deviceId = @"16b8f4bdfd55d29f737427b4ec0c14d7";
    NSString *deviceIdSha256  = [EncryptionUtils sha256Hash:[deviceId dataUsingEncoding:NSUTF8StringEncoding]];
    NSRange range = NSMakeRange(32, 32);
    NSString *deviceIdSha256Sub = [deviceIdSha256 substringWithRange:range];
    NSLog(@"deviceIdSha256: %@",deviceIdSha256);
    NSLog(@"deviceIdSha256Sub: %@",deviceIdSha256Sub);
    
//    unsigned char charArray[] = {1, 4, 2};
    unsigned char charArray[] = {3, 4, 2};
    NSUInteger length = sizeof(charArray) / sizeof(unsigned char);
    NSString *string = @"NSExtension"; // 后面的字符串
    // 将字符串转换为NSData对象
    NSData *stringData = [string dataUsingEncoding:NSUTF8StringEncoding];
    // 创建NSMutableData对象
    NSMutableData *data = [NSMutableData dataWithBytes:charArray length:length];
    // 将字符串数据追加到NSMutableData中
    [data appendData:stringData];
    
    // 加密
//    NSData *key = [[NSData alloc] initWithBase64EncodedString:@"t2q/dZkHDYceWWjzhEp5wGrzfYKvgaKEOX4KzPKDyyQ=" options:0];
    NSData *key = [EncryptionUtils hexStringToBytes:deviceIdSha256];
//    NSData *iv = [[NSData alloc] initWithBase64EncodedString:@"avN9gq+BooQ5fgrM8oPLJA==" options:0];
    NSData *iv = [EncryptionUtils hexStringToBytes:deviceIdSha256Sub];
    
    NSData *encryptedData = [EncryptionUtils cccEncryptData:data withKey:key iv:iv];
    NSString *encryptedDataBase64 = [encryptedData base64EncodedStringWithOptions:0];
    NSLog(@"encryptedDataBase64: %@", encryptedDataBase64); // 5HxqsB1DW2UPHea90LJ4mA==
    NSLog(@"Encrypted data: %@", encryptedData);
    
    
    
    
    bool is_pkcs8 = true;
    NSString *publicKeyStr = @"-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvnU72zbRQFSB7IZ4ob2u\n"
    "4YgjsI6507rjwhR5DzxZBPtxuAuQOJnCM6XqrFy0hUazNDUybmVb+abbQlbmHs9C\n"
    "MGsYLpYKqJLNFCGy+2CRJxCLrTE35pJ36zIVvdj+1qH2KfyfiEjBc6+F6W3E0TwW\n"
    "BMd0ezj1pWYZoCytabmhgvhumWXI0ReOIGLuMrEOAf8zKZBWRRVSW3cLSwq0eQ7u\n"
    "ubi5UD5rvkmcDuL+RUQySi4W8vOpteq3ceZmtZVpUAXvUjnXzg/EX94VVfPCWhd1\n"
    "Ii4P+EBkaV7SuqFgZiczmkcXin5JrkATnIEf5pi71XWadeVZgFSOrkseCQE+Twta\n"
    "9QIDAQAB\n"
    "-----END PUBLIC KEY-----\n";
    
    NSString *privateKeyStr =@"-----BEGIN PRIVATE KEY-----\n"
    "MIIBLwIBADANBgkqhkiG9w0BAQEFAASCARswggSlAgEAAoIBAQC+dTvbNtFAVIHs\n"
    "hnihva7hiCOwjrnTuuPCFHkPPFkE+3G4C5A4mcIzpeqsXLSFRrM0NTJuZVv5pttC\n"
    "VuYez0Iwaxgulgqoks0UIbL7YJEnEIutMTfmknfrMhW92P7WofYp/J+ISMFzr4Xp\n"
    "bcTRPBYEx3R7OPWlZhmgLK1puaGC+G6ZZcjRF44gYu4ysQ4B/zMpkFZFFVJbdwtL\n"
    "CrR5Du65uLlQPmu+SZwO4v5FRDJKLhby86m16rdx5ma1lWlQBe9SOdfOD8Rf3hVV\n"
    "88JaF3UiLg/4QGRpXtK6oWBmJzOaRxeKfkmuQBOcgR/mmLvVdZp15VmAVI6uSx4J\n"
    "AT5PC1r1AgMBAAECggEBAJqsyve1BSuhdgKJEt8IFUbEMXfp8bCqTt4Hkml1MTaC\n"
    "nlBB09ajyLv5OyTQBStXx6HWsiZF2vRdNiQiPrE20SJRV0o+QFm3HyYCWEEeo8N+\n"
    "BHGbTzLKMOmpu057NDtLPYfLyiP8Ml+pZK+2nejvS1KGSWrpT1YMHTOgFRWP1ENv\n"
    "5TGZAHsk4pizHrr8Eco5R2yavA16gdlkOCGdIhn2rv9xCcy+snUPZ0hNHAaMbo5z\n"
    "xPnaBDgKje2PK/R+FuCmTERD07Tdju3q4WOz+J3Qr+8fRz/fJ0ZtKUFVcCTN9H+t\n"
    "Lv3a9TThq58b0rzIzoWxpUK5yOI7INnRVFqv4NmMIuECgYEA/Mnpah18px1VRYEs\n"
    "7OBUUniuwQUuOZdxu90IgY8tAjWsF1eFGc5borKkc2l5iA6aTjIv//sjhgeMcKu1\n"
    "8FstLwRqEZcooc8JV5SiHufe6JNpozu5SqTfRMoMe5PqE3bYigJZGCenj2sg1juI\n"
    "fNMzA+Y2KbEVT3uNmpGYQDJIxTMCgYEAwOCeGxzbhPDdI8vmMGp0bBJWeotUCJ/S\n"
    "R6rbWxcDtCc89MnuYuNqPW5O6eJBAF+BX/KtH6hQayIaHgn6gcYvdX0aCeU+niSo\n"
    "fmz8Yw/6YMUGu1B8mZsmjeiVlFAJDq4tuOvfiC5UoyBLTtJLfNoCqRZJvTM7//Qf\n"
    "6a998lS5DzcCgYEA5C4KANxPCbYjo5Kfj85Krwr6i4b2m8vFQROauwAXW5hBF+zL\n"
    "W2j3NFxWr0r1BchQpucMht8VyMUFkyqcFzLmDTvJ1skAR1bQEvs6f/VDM+LkhxDB\n"
    "B8zdMIXFUMNKlnk/qwvFilU5He9Qe7DPWgV2Vj22hFmxZ8aaInzr1n7NSxsCgYB/\n"
    "PS7QMA9Y+hTIoqBuXCwFh2tpWDTNo7Fy+fHPe7VDyYba7cPHlMLnV7fTbyD2gAq3\n"
    "Iz62XbD/m/Wiz25k4js4xJjC4mqWpRRKotc0+rtvz0qLk6M/Ki0a/M6AkvQGrT0Y\n"
    "evJxwi6vloRXsT9/U8rhhQSMPhpc1c2fudfaX63drQKBgQCufuK+gLZiTKrXMbI/\n"
    "vQ5aJoW4eKKC7SywGHwt1KklB6BsHG0xdScPVBIGzsD1Q9AFjKz75hMfRiz9s2YN\n"
    "+lI8vdnIh7UJSc26NMKOsdZpFsC2rFRjgYvxAg/ucZnHqm+Zal7M4p0+k4IhBSSu\n"
    "73dR4J1mcJ7YM9Pvx5jkFP87cg==\n"
    "-----END PRIVATE KEY-----\n";
    NSLog(@"publicKeyStr: %@",publicKeyStr);
    NSLog(@"privateKeyStr: %@",privateKeyStr);
    
    
    NSDictionary *jsonLicense = @{
        @"deviceID": deviceId,
        @"type":@"licensed",
        @"product": @"SURGEMAC5",
        @"expiresOnDate": @1746350567,
        @"p": encryptedDataBase64
    };
    
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:jsonLicense options:NSJSONWritingPrettyPrinted error:nil];
    NSString *text = [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    
    NSString *textBase64 = [[text dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
    
    NSLog(@"textBase64 :%@",textBase64);
    
    // sign 生成
    NSData *sign = [EncryptionUtils generateSignatureForData:[text dataUsingEncoding:NSUTF8StringEncoding] privateKey:privateKeyStr isPKCS8:is_pkcs8];
    NSString *signBase64 = [sign base64EncodedStringWithOptions:0];
    
    // sign 验证
    NSLog(@"signBase64: %@",signBase64);
    Boolean verify = [EncryptionUtils verifySignatureWithBase64:textBase64 signature:signBase64 publicKey:publicKeyStr isPKCS8:is_pkcs8];
    NSLog(@"verify: %hhu",verify);
   
    
}




- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
        
        
    }];
}

@end
