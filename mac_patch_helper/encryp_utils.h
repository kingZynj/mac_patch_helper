//
//  encryp_utils.h
//  mac_patch_helper
//
//  Created by 马治武 on 2024/5/3.
//

#ifndef encryp_utils_h
#define encryp_utils_h

@interface EncryptionUtils : NSObject

+ (NSString *)generateTablePlusDeviceId;

+ (NSString *)generateSurgeDeviceId;
+ (NSString *)calculateMD5:(NSString *) input;

+ (NSDictionary *)generateKeyPair:(bool)is_pkcs8;
+ (NSData *)generateSignatureForData:(NSData *)data privateKey:(NSString *)privateKeyString isPKCS8:(bool)is_pkcs8;

+ (BOOL)verifySignatureWithBase64:(NSString *)policy signature:(NSString *)sign publicKey:(NSString *)publicKeyString isPKCS8:(bool)is_pkcs8;
+ (BOOL)verifySignatureWithByte:(NSData *)policyData signature:(NSData *)signData publicKey:(NSString *)publicKeyString isPKCS8:(bool)is_pkcs8;


+ (NSData *)rsaEncryptData:(NSData *)data withPublicKey:(NSString *)publicKeyString isPKCS8:(bool)is_pkcs8;
+ (NSData *)rsaDecryptData:(NSData *)data withPrivateKey:(NSString *)privateKeyString isPKCS8:(bool)is_pkcs8;

    
+ (NSString *)convertToPEMFormat:(NSData *)keyData withKeyType:(NSString *)keyType;


+ (NSData *)cccEncryptData:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv;
+ (NSData *)cccDecryptData:(NSData *)data withKey:(NSData *)key iv:(NSData *)iv;


+ (NSData *)hexStringToBytes:(NSString*)hexString;
+ (NSString *)base64Encode:(NSData*)data;
+ (NSString *)sha256Hash:(NSData *)data;

@end
#endif /* encryp_utils_h */
