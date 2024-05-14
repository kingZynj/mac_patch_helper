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
    
    // 加密
    NSData *sign = [EncryptionUtils generateSignatureForData:[text dataUsingEncoding:NSUTF8StringEncoding] privateKey:privateKeyStr isPKCS8:is_pkcs8];
    NSString *signBase64 = [sign base64EncodedStringWithOptions:0];
    
    // 验证
    NSLog(@"signBase64: %@",signBase64);
    Boolean verify = [EncryptionUtils verifySignatureWithBase64:textBase64 signature:signBase64 publicKey:publicKeyStr isPKCS8:is_pkcs8];
    NSLog(@"verify: %hhu",verify);
    
    
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
    
    // 加密
    NSData *sign = [EncryptionUtils generateSignatureForData:[text dataUsingEncoding:NSUTF8StringEncoding] privateKey:privateKeyStr isPKCS8:is_pkcs8];
    NSString *signBase64 = [sign base64EncodedStringWithOptions:0];
    
    // 验证
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
