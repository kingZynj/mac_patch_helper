//
//  utils.h
//  mac_patch_helper
//
//  Created by 马治武 on 2024/4/9.
//

#ifndef utils_h
#define utils_h
NSData *machineCode2Bytes(NSString *hexString);
void replaceMachineCodeAtOffsets(NSString *filePath, NSArray<NSNumber *> *offsets, NSString *newMachineCode);
NSArray *searchMachineCodeOffsets(NSString *searchFilePath, NSString *searchMachineCode ,int count);

NSString *extractMiddleText(NSString *inputString, NSString *startString, NSString *endString);

void replaceCertificateInFile(NSString *filePath);

BOOL backupFileIfNeeded(NSString *filePath);
#endif /* utils_h */
