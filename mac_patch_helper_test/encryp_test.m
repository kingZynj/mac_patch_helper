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

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
        
        
    }];
}

@end
