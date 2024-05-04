//
//  encryp_utils.h
//  mac_patch_helper
//
//  Created by 马治武 on 2024/5/3.
//

#ifndef encryp_utils_h
#define encryp_utils_h

@interface EncryptionUtils : NSObject

+ (NSDictionary *)generateKeyPair;
+ (NSData *)generateSignatureForData:(NSData *)data privateKey:(NSString *)privateKeyString;

+ (BOOL)verifySignatureWithBase64:(NSString *)policy signature:(NSString *)sign publicKey:(NSString *)publicKeyString;
+ (BOOL)verifySignatureWithByte:(NSData *)policyData signature:(NSData *)signData publicKey:(NSString *)publicKeyString;

+ (NSString *)convertToPEMFormat:(NSData *)keyData withKeyType:(NSString *)keyType;
@end
#endif /* encryp_utils_h */
