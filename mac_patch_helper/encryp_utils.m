//
//  entry_utils.m
//  mac_patch_helper
//
//  Created by 马治武 on 2024/5/3.
//

#import <Foundation/Foundation.h>
#import "encryp_utils.h"

@implementation EncryptionUtils


+ (BOOL)verifySignatureWithBase64:(NSString *)policy signature:(NSString *)sign publicKey:(NSString *)publicKeyString{
    
    NSData *policyData = [[NSData alloc] initWithBase64EncodedString:policy options:0];
    NSData *signData = [[NSData alloc] initWithBase64EncodedString:sign options:0];
    return [self verifySignatureWithByte:policyData signature:signData publicKey:publicKeyString];
    
    
}

+ (BOOL)verifySignatureWithByte:(NSData *)policyData signature:(NSData *)signData publicKey:(NSString *)publicKeyString {
    NSArray *components = [publicKeyString componentsSeparatedByString:@"\n"];
    NSMutableArray *cleanedComponents = [NSMutableArray arrayWithArray:components];
    [cleanedComponents removeObject:@""];
    [cleanedComponents removeObject:@"-----BEGIN PUBLIC KEY-----"];
    [cleanedComponents removeObject:@"-----END PUBLIC KEY-----"];
    
    // 将剩余的字符串拼接为单个字符串
    NSString *cleanedString = [cleanedComponents componentsJoinedByString:@""];
    
    // 解码 Base64 字符串为 NSData
    NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:cleanedString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    // 创建公钥字典
    NSDictionary *attributes = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
    };
    
    SecKeyRef publicKey = NULL;
    // 创建公钥对象
    CFErrorRef error1 = NULL;
    publicKey = SecKeyCreateWithData((__bridge CFDataRef)publicKeyData, (__bridge CFDictionaryRef)attributes, &error1);
    
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    BOOL verificationResult = SecKeyVerifySignature(publicKey, algorithm, (__bridge CFDataRef)policyData, (__bridge CFDataRef)signData, NULL);
    
    return verificationResult;
}

@end
