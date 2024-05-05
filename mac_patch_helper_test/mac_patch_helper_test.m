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

@interface mac_patch_helper_test : XCTestCase

@end

@implementation mac_patch_helper_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}





- (void) test_tmp {

    
    
    NSString *message = @"Hello, CCCrypt!";
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    
    // 加密
    NSData *key = [@"0123456789012345" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *iv = [@"abcdefghijklmnop" dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *encryptedData = [EncryptionUtils cccEncryptData:data withKey:key iv:iv];
    
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
- (void)test_encyp {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
    // 生成公钥私钥
    bool is_pkcs8 = true;
    NSDictionary * keys = [EncryptionUtils generateKeyPair:is_pkcs8];
    NSString *publicKeyStr = [keys objectForKeyedSubscript:@"publicKey"];
    NSString *privateKeyStr = [keys objectForKeyedSubscript:@"privateKey"];
    NSLog(@"publicKeyStr: %@",publicKeyStr);
    NSLog(@"privateKeyStr: %@",privateKeyStr);

    // eyJkZXZpY2VJRCI6IjM2ZDdhOTdhOTFiODJjZTViYzhiMjYwOWQ0ZTE3ZGFlIiwidHlwZSI6ImxpY2Vuc2VkIiwicHJvZHVjdCI6IlNVUkdFTUFDNSIsImV4cGlyZXNPbkRhdGUiOiIxNzQ2MzUwNTY3In0=
    NSString *text =@"{\"deviceID\":\"36d7a97a91b82ce5bc8b2609d4e17dae\",\"type\":\"trial\",\"product\":\"SURGEMAC5\",\"expiresOnDate\":\"1746350567\",\"p\":\"123\"}";
    NSString *textBase64 = [[text dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];

    NSLog(@"textBase64 :%@",textBase64);

    
    
    // 加密
    NSData *sign = [EncryptionUtils generateSignatureForData:[text dataUsingEncoding:NSUTF8StringEncoding]privateKey:(NSString *)privateKeyStr:is_pkcs8];
    NSString *signBase64 = [sign base64EncodedStringWithOptions:0];
    
    // 验证
    NSLog(@"signBase64: %@",signBase64);
    Boolean verify = [EncryptionUtils verifySignatureWithBase64:textBase64 signature:signBase64 publicKey:publicKeyStr:is_pkcs8];
    NSLog(@"verify: %hhu",verify);
    
   
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
        
        
    }];
}

@end
