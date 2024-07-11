//
//  ClzTest.m
//  mac_patch_helper_test
//
//  Created by 马治武 on 2024/5/16.
//

#import <XCTest/XCTest.h>

@interface NSString (MyExtension)

- (BOOL)myCustomMethodWithParameter:(NSString *)parameter;

@end

@implementation NSString (MyExtension)

- (BOOL)myCustomMethodWithParameter:(NSString *)parameter {
    // 在这里实现自定义方法的逻辑
    // 可以访问 self 对象的属性和方法，并使用传入的参数
    
    // 示例逻辑：将传入的参数拼接到当前字符串后面
    return false;
}

@end



@interface ClzTest : XCTestCase

@end

@implementation ClzTest

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}
int myCFunction(int arg1,int arg2,int arg3) {
    return 0;
}

- (void)testExample {
    SEL mySelector = @selector(myCustomMethodWithParameter:);

    NSString * str1 = @"a";
    NSString * str2 = @"a";
    
    bool ret = [str1 isEqualToString:str2];
    NSLog(@"[str1 isEqualToString:str2] : %d",ret);
    

    BOOL isEqual = (BOOL)[str1 performSelector:mySelector withObject:str2];
    NSLog(@"[isEqual] : %d",isEqual);

//    if ([str1 respondsToSelector:mySelector]) {
//        NSLog(@"isEqual: %d", isEqual);
//    } else {
//        NSLog(@"str1 does not respond to the selector");
//    }
}

uint8_t *intptrToUint8Array(intptr_t value, size_t outputLength) {
    // 确保outputLength足够大以存储intptr_t的字节表示
    size_t valueSize = sizeof(value);
    if (outputLength < valueSize) {
        // 数组太小，无法存储整个值
        return NULL;
    }
      
    // 在堆上分配数组
    uint8_t *result = (uint8_t *)malloc(outputLength * sizeof(uint8_t));
    if (result == NULL) {
        // 内存分配失败
        return NULL;
    }
      
    // 将intptr_t的字节表示复制到数组中（小端序）
    for (size_t i = 0; i < valueSize; i++) {
        result[i] = (uint8_t)((value >> (i * CHAR_BIT)) & 0xFF);
    }
      
    // 填充剩余的数组位置为0
    for (size_t i = valueSize; i < outputLength; i++) {
        result[i] = 0;
    }
      
    return result;
}

- (void)test_intptrToUint8Array {
    intptr_t value = 0x7ED26A; // 在64位系统上，这将被扩展为一个64位值
    size_t outputLength = 8; // 我们只想要4个字节的数组
      
    uint8_t *nop4 = intptrToUint8Array(value, outputLength);
    NSLog(@"%@",nop4);
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
