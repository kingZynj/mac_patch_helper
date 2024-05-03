//
//  entry_utils.m
//  mac_patch_helper
//
//  Created by 马治武 on 2024/5/3.
//

#import <Foundation/Foundation.h>
#import "encryp_utils.h"

@implementation EncryptionUtils

+ (NSDictionary *)generateKeyPair {
    // 设置密钥参数
    NSDictionary *parameters = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeySizeInBits: @2048,
    };
    
    // 生成密钥对
    SecKeyRef publicKey, privateKey;
    OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
    
    if (status != errSecSuccess) {
        NSLog(@"Failed to generate key pair");
        return nil;
    }
    
    // 将密钥转换为字符串
    NSData *publicKeyData = CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, nil));
    NSData *privateKeyData = CFBridgingRelease(SecKeyCopyExternalRepresentation(privateKey, nil));
    NSString *publicKeyString = [publicKeyData base64EncodedStringWithOptions:0];
    NSString *privateKeyString = [privateKeyData base64EncodedStringWithOptions:0];
    
    // 返回密钥对
    return @{
        @"publicKey": publicKeyString,
        @"privateKey": privateKeyString
    };
}

+ (NSData *)generateSignatureForData:(NSData *)data privateKey:(NSString *)privateKeyString {
    // 解码 Base64 字符串为 NSData
    NSData *privateKeyData = [[NSData alloc] initWithBase64EncodedString:privateKeyString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    // 创建私钥字典
    NSDictionary *attributes = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
    };
    
    SecKeyRef privateKey = NULL;
    // 创建私钥对象
    CFErrorRef error = NULL;
    privateKey = SecKeyCreateWithData((__bridge CFDataRef)privateKeyData, (__bridge CFDictionaryRef)attributes, &error);
    
    // 签名数据
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256;
    CFDataRef signedDataRef = SecKeyCreateSignature(privateKey, algorithm, (__bridge CFDataRef)data, &error);
    
    NSData *signedData = (__bridge NSData *)signedDataRef;
    
    if (error != NULL) {
        NSLog(@"Signature generation failed: %@", (__bridge NSError *)error);
        if (signedDataRef != NULL) {
            CFRelease(signedDataRef);
        }
        return nil;
    }
    
    return signedData;
}


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
