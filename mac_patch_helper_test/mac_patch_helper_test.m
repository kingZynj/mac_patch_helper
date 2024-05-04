//
//  mac_patch_helper_test.m
//  mac_patch_helper_test
//
//  Created by 马治武 on 2024/5/4.
//

#import <XCTest/XCTest.h>
#import "encryp_utils.h"

@interface mac_patch_helper_test : XCTestCase

@end

@implementation mac_patch_helper_test

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

- (void)test_encyp {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
    // 生成公钥私钥
    NSDictionary * keys = [EncryptionUtils generateKeyPair];
    NSString *publicKeyStr = [keys objectForKeyedSubscript:@"publicKey"];
    NSString *privateKeyStr = [keys objectForKeyedSubscript:@"privateKey"];
    NSLog(@"keys: %@",keys);

    // helloworld :aGVsbG93b3JsZA==
    NSString *text =@"helloworld";

    // 加密
    NSData *sign = [EncryptionUtils generateSignatureForData:[text dataUsingEncoding:NSUTF8StringEncoding]privateKey:(NSString *)privateKeyStr];
    NSString *signBase64 = [sign base64EncodedStringWithOptions:0];
    
    // 验证
    NSLog(@"signBase64: %@",signBase64);
    Boolean verify = [EncryptionUtils verifySignatureWithBase64:@"aGVsbG93b3JsZA==" signature:signBase64 publicKey:publicKeyStr];
    NSLog(@"verify: %hhu",verify);
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
        
        
    }];
}

@end
