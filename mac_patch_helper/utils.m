//
//  utils.m
//  mac_patch_helper
//
//  Created by 马治武 on 2024/4/9.
//

#import <Foundation/Foundation.h>




NSData *machineCode2Bytes(NSString *hexString) {
    NSMutableData *data = [NSMutableData new];
    NSCharacterSet *whitespace = [NSCharacterSet whitespaceAndNewlineCharacterSet];
    hexString = [[hexString componentsSeparatedByCharactersInSet:whitespace] componentsJoinedByString:@""];

    for (NSUInteger i = 0; i < [hexString length]; i += 2) {
        NSString *byteString = [hexString substringWithRange:NSMakeRange(i, 2)];
        if ([byteString isEqualToString:@"??"]) {
            uint8_t byte = (uint8_t) 144;
            [data appendBytes:&byte length:1];
            continue;
        }
        NSScanner *scanner = [NSScanner scannerWithString:byteString];
        unsigned int byteValue;
        [scanner scanHexInt:&byteValue];
        uint8_t byte = (uint8_t) byteValue;
        [data appendBytes:&byte length:1];
    }
    return [data copy];
}


void replaceMachineCodeAtOffsets(NSString *filePath, NSArray<NSNumber *> *offsets, NSString *newMachineCode) {
    if (offsets.count == 0) {
        NSLog(@"No offsets provided for replacement");
        return;
    }
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForUpdatingAtPath:filePath];
    if (fileHandle == nil) {
        NSLog(@"Error: Failed to open file for updating at path %@", filePath);
        return;
    }
    NSData *newBytes = machineCode2Bytes(newMachineCode);
    // NSUInteger newLength = [newBytes length];
    for (NSNumber *offsetNumber in offsets) {
        NSUInteger offset = [offsetNumber unsignedIntegerValue];
        [fileHandle seekToFileOffset:offset];
        [fileHandle writeData:newBytes];
    }
    [fileHandle closeFile];
}


/*
 * 特征吗搜索
 * ? 匹配所有
 */
NSArray *searchMachineCodeOffsets(NSString *searchFilePath, NSString *searchMachineCode ,int count) {
        
    searchMachineCode = [searchMachineCode stringByReplacingOccurrencesOfString:@"." withString:@"?"];    
    NSFileHandle *fileHandle = [NSFileHandle fileHandleForReadingAtPath:searchFilePath];

    NSMutableArray<NSNumber *> *offsets = [NSMutableArray array];
    NSData *fileData = [fileHandle readDataToEndOfFile];
    NSUInteger fileLength = [fileData length];

    NSData *searchBytes = machineCode2Bytes(searchMachineCode);
    NSUInteger searchLength = [searchBytes length];
    NSUInteger matchCounter = 0;
    
    for (NSUInteger i = 0; i < fileLength - searchLength + 1; i++) {
         BOOL isMatch = YES;
         for (NSUInteger j = 0; j < searchLength; j++) {
             uint8_t fileByte = ((const uint8_t *)[fileData bytes])[i + j];
             // if (i>364908 && i<364930) {
             //     NSLog(@">>>>>> %d : %p",i,fileByte);
             // }
             uint8_t searchByte = ((const uint8_t *)[searchBytes bytes])[j];
             if (searchByte != 0x90 && fileByte != searchByte) {
                 isMatch = NO;
                 break;
             }
         }
         if (isMatch) {
             [offsets addObject:@(i)];
             matchCounter++;
             if (matchCounter >= count) {
                 break;
             }
         }
     }
    [fileHandle closeFile];
    return [offsets copy];
}




NSString *extractMiddleText(NSString *inputString, NSString *startString, NSString *endString) {
    NSRange startRange = [inputString rangeOfString:startString];
    if (startRange.location == NSNotFound) {
        return nil;
    }
    
    NSRange searchRange = NSMakeRange(startRange.location + startRange.length, inputString.length - (startRange.location + startRange.length));
    NSRange endRange = [inputString rangeOfString:endString options:0 range:searchRange];
    if (endRange.location == NSNotFound) {
        return nil;
    }
    
    NSRange middleRange = NSMakeRange(startRange.location + startRange.length, endRange.location - (startRange.location + startRange.length));
    NSString *middleText = [inputString substringWithRange:middleRange];
    
    return middleText;
}

void replaceCertificateInFile(NSString *filePath) {
    NSData *originalData = [NSData dataWithContentsOfFile:filePath];
    NSMutableData *modifiedData = [originalData mutableCopy];
    
    // <key>SMAuthorizedClients</key>:\x3C\x6B\x65\x79\x3E\x53\x4D\x41\x75\x74\x68\x6F\x72\x69\x7A\x65\x64\x43\x6C\x69\x65\x6E\x74\x73\x3C\x2F\x6B\x65\x79\x3E
    const char *searchBytes = "\x3C\x6B\x65\x79\x3E\x53\x4D\x41\x75\x74\x68\x6F\x72\x69\x7A\x65\x64\x43\x6C\x69\x65\x6E\x74\x73\x3C\x2F\x6B\x65\x79\x3E";
    // </array>:\x3C\x2F\x61\x72\x72\x61\x79\x3E
    // 09:\t , 0A:\n
    const char *endBytes = "\x0A\x09\x3C\x2F\x61\x72\x72\x61\x79\x3E";

    
    const char *paddingByte = "\x09";
    
    NSUInteger searchLength = strlen(searchBytes);
    NSUInteger endLength = strlen(endBytes);
    NSUInteger paddingLength = strlen(paddingByte);
    
    NSRange searchRange = [modifiedData rangeOfData:[NSData dataWithBytes:searchBytes length:searchLength] options:0 range:NSMakeRange(0, modifiedData.length)];
    
    while (searchRange.location != NSNotFound) {
        NSUInteger searchEndLocation = searchRange.location + searchRange.length;
        NSRange endRange = [modifiedData rangeOfData:[NSData dataWithBytes:endBytes length:endLength] options:0 range:NSMakeRange(searchEndLocation, modifiedData.length - searchEndLocation)];
        
        if (endRange.location != NSNotFound) {
            NSUInteger replaceStartLocation = searchRange.location + searchRange.length;
            NSUInteger replaceEndLocation = endRange.location;
            NSRange replaceRange = NSMakeRange(replaceStartLocation, replaceEndLocation - replaceStartLocation);
            
            NSString *replaceString = [[NSString alloc] initWithData:[modifiedData subdataWithRange:replaceRange] encoding:NSUTF8StringEncoding];            
            // <string>anchor apple generic and identifier &quot;com.nssurge.surge-mac&quot; and (certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = &quot;YCKFLA6N72&quot;)</string>
            NSString *identifier = extractMiddleText(replaceString,@"identifier &quot;",@"&quot; ");
            if (identifier==nil) {
                NSLog(@"Original identifier not found, Will be continue !");
                searchRange = [modifiedData rangeOfData:[NSData dataWithBytes:searchBytes length:searchLength] options:0 range:NSMakeRange(searchRange.location + searchRange.length, modifiedData.length - (searchRange.location + searchRange.length))];
                continue;
            }
            NSLog(@"Original string: %@", replaceString);
            NSLog(@"Original identifier: %@", identifier);
            
            
            
            NSString *replacedString = [@"<string>identifier &quot;{}&quot;</string>" stringByReplacingOccurrencesOfString:@"{}" withString:identifier];
//            NSString *replacedString = [@"<string>identifier \"{}\"</string>" stringByReplacingOccurrencesOfString:@"{}" withString:identifier];
            const char *replaceBytes = [replacedString UTF8String];
//            <string>identifier "com.nssurge.surge-mac"</string>
//            const char *replaceBytes = "\x3C\x73\x74\x72\x69\x6E\x67\x3E\x69\x64\x65\x6E\x74\x69\x66\x69\x65\x72\x20\x22\x63\x6F\x6D\x2E\x6E\x73\x73\x75\x72\x67\x65\x2E\x73\x75\x72\x67\x65\x2D\x6D\x61\x63\x22\x3C\x2F\x73\x74\x72\x69\x6E\x67\x3E";
            
            NSUInteger replaceLength = strlen(replaceBytes);

            NSRange certificateRange = [replaceString rangeOfString:@"<string>.+identifier.+</string>" options:NSRegularExpressionSearch];
            
            if (certificateRange.location != NSNotFound) {
                NSString *modifiedString = [replaceString stringByReplacingCharactersInRange:certificateRange withString:[[NSString alloc] initWithUTF8String:replaceBytes]];
//                NSString *modifiedString = [replaceString stringByReplacingCharactersInRange:certificateRange withString:replaceString];

                NSData *modifiedSubData = [modifiedString dataUsingEncoding:NSUTF8StringEncoding];
                [modifiedData replaceBytesInRange:replaceRange withBytes:modifiedSubData.bytes length:modifiedSubData.length];
                
                // Padding with 0A bytes
                NSUInteger paddingCount = certificateRange.length - replaceLength;
                NSMutableData *paddingData = [NSMutableData dataWithCapacity:paddingCount];
                for (NSUInteger i = 0; i < paddingCount; i++) {
                    [paddingData appendBytes:paddingByte length:paddingLength];
                }
//              Calc  Padding range
                [modifiedData replaceBytesInRange:NSMakeRange(replaceRange.location + replaceRange.length - paddingCount , 0) withBytes:paddingData.bytes length:paddingData.length];

                NSLog(@"Modified string: %@", modifiedString);
                NSLog(@"Replace range: %@", NSStringFromRange(replaceRange));
                NSLog(@"Padding count: %lu", (unsigned long)paddingCount);
            }
            
        }
        
        searchRange = [modifiedData rangeOfData:[NSData dataWithBytes:searchBytes length:searchLength] options:0 range:NSMakeRange(searchRange.location + searchRange.length, modifiedData.length - (searchRange.location + searchRange.length))];
    }
    
    [modifiedData writeToFile:filePath atomically:YES];
    return;
}

// Function to backup file
BOOL backupFileIfNeeded(NSString *filePath) {
    NSString *backupPath = [filePath stringByAppendingString:@".bak"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:backupPath]) {
        NSLog(@"Backup file already exists at path [%@]", backupPath);
        return YES;
    }
    
    NSError *error = nil;
    if (![[NSFileManager defaultManager] copyItemAtPath:filePath toPath:backupPath error:&error]) {
        NSLog(@"Error: Failed to backup file [%@]: [%@]", filePath, error);
        return NO;
    }
    
    NSLog(@"File backed up successfully to [%@]", backupPath);
    return YES;
}
