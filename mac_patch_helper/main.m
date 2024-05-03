//
//  main.m
//  mac_patch_helper
//
//  Created by 马治武 on 2024/4/9.
//

#import <Foundation/Foundation.h>
#import "utils.h"


int main(int argc, const char * argv[]) {
    @autoreleasepool {
        
        
        if (argc < 2) {
            NSLog(@"Usage: %s <app_name>", argv[0]);
            return 1;
        }
        
        // Check if patchFilePath argument is provided
        // NSString *patchFilePath = @"/Users/voidm/Downloads/patch.json";
        NSString *patchFilePath;
        if (argc == 3) {
            patchFilePath = [NSString stringWithUTF8String:argv[2]];
        } else {
            // Default to current directory
            patchFilePath = @"patch.json";
        }
        
        NSLog(@"patchFilePath: [%@] ", patchFilePath);

        
        NSString *appName = [NSString stringWithUTF8String:argv[1]];
        NSLog(@"appName: [%@] ", appName);
        
        // Read patch.json
        
        NSData *jsonData = [NSData dataWithContentsOfFile:patchFilePath];
        if (jsonData == nil) {
            NSLog(@"Error: Failed to read patch.json file");
            return 1;
        }
        
        NSError *error = nil;
        NSDictionary *patchData = [NSJSONSerialization JSONObjectWithData:jsonData options:kNilOptions error:&error];
        if (patchData == nil) {
           NSLog(@"Error: Failed to parse patch.json file: [%@]", error);
           return 1;
        }
        
        // Get patch data for the specified app
        NSDictionary *appPatchData = patchData[appName];
        if (appPatchData == nil) {
            NSLog(@"Error: No patch data found for [%@]", appName);
            return 1;
        }
        
        
        
        // Apply patches
        NSDictionary *patch = appPatchData[@"patch"];
        for (NSString *plistFile in patch) {
            backupFileIfNeeded(plistFile);
            NSDictionary *patchForPlist = patch[plistFile];
            NSLog(@"patchForPlist: [%@] , %@", plistFile,patchForPlist);
            NSDictionary *x86Data = patchForPlist[@"x86"];
            
            if (x86Data) {
                for (NSString *searchMachineCode in x86Data) {
                    NSString *newMachineCode = x86Data[searchMachineCode];
                    NSArray *offsets = searchMachineCodeOffsets(plistFile, searchMachineCode, 1);
                    NSLog(@"x86 offsets: %@ -> %@",searchMachineCode,offsets);
                    if (offsets.count > 0) {
                        replaceMachineCodeAtOffsets(plistFile, offsets, newMachineCode);
                        NSLog(@"Replaced machine code for file [%@] with new machine code: [%@]", plistFile, newMachineCode);
                    } else {
                        NSLog(@"Machine code not found for file [%@] and search machine code [%@]", plistFile, searchMachineCode);
                    }
                }
            }
            
            NSDictionary *armData = patchForPlist[@"arm"];
            
            if (armData) {
                for (NSString *searchMachineCode in armData) {
                    NSString *newMachineCode = armData[searchMachineCode];
                    NSArray *offsets = searchMachineCodeOffsets(plistFile, searchMachineCode, 1);
                    NSLog(@"arm offsets: %@ -> %@",searchMachineCode,offsets);
                    if (offsets.count > 0) {
                        replaceMachineCodeAtOffsets(plistFile, offsets, newMachineCode);
                        NSLog(@"Replaced machine code for file [%@] with new machine code: [%@]", plistFile, newMachineCode);
                    } else {
                        NSLog(@"Machine code not found for file [%@] and search machine code [%@]", plistFile, searchMachineCode);
                    }
                }
            }

        }
        
        // Clear certificates
        NSArray *certificatesToClear = appPatchData[@"clear_certificate"];
        for (NSString *certificatePath in certificatesToClear) {
            backupFileIfNeeded(certificatePath);
            NSLog(@"certificatesToClear: [%@]", certificatePath);
            replaceCertificateInFile(certificatePath);
        }
    }
    return 0;
}
