//
//  encryp_utils.h
//  mac_patch_helper
//
//  Created by 马治武 on 2024/5/3.
//

#ifndef encryp_utils_h
#define encryp_utils_h


//NSDictionary * keys = [EncryptionUtils generateKeyPair];
//NSString *publicKeyStr = [keys objectForKeyedSubscript:@"publicKey"];
//NSString *privateKeyStr = [keys objectForKeyedSubscript:@"privateKey"];
//// helloworld :aGVsbG93b3JsZA==
//NSString *text =@"helloworld";
//NSData *sign = [EncryptionUtils generateSignatureForData:[text dataUsingEncoding:NSUTF8StringEncoding]privateKey:(NSString *)privateKeyStr];
//NSString *signBase64 = [sign base64EncodedStringWithOptions:0];
//
//NSLog(@"signBase64: %@",signBase64);
//Boolean verify = [EncryptionUtils verifySignatureWithBase64:@"aGVsbG93b3JsZA==" signature:signBase64 publicKey:publicKeyStr];
//NSLog(@"verify: %hhu",verify);

@interface EncryptionUtils : NSObject

+ (NSDictionary *)generateKeyPair;
+ (NSData *)generateSignatureForData:(NSData *)data privateKey:(NSString *)privateKeyString;

+ (BOOL)verifySignatureWithBase64:(NSString *)policy signature:(NSString *)sign publicKey:(NSString *)publicKeyString;
+ (BOOL)verifySignatureWithByte:(NSData *)policyData signature:(NSData *)signData publicKey:(NSString *)publicKeyString;

@end
#endif /* encryp_utils_h */
