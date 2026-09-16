rule tree2 {
  strings:
    $s0    = "ZL22copySwiftV1MangledNamePKcb" fullword
    $s1    = "category23default" fullword
    $s2    = "didUpdateUserActivity" fullword
    $s3    = "callToActionTitleForWelcomeViewController" fullword
    $s4    = "scanJSONKeyValueSeparator" fullword
    $s5    = "supportsUIRestoring" fullword
    $s6    = "constants10error" fullword
    $s7    = "ZTSN5boost18thread" fullword
    $s8    = "setStandardOutput" fullword
    $s9    = "RequestFPGACount" fullword
    $s10   = "initWithFireDate" fullword
    $s11   = "getCursorPosition" fullword
    $s12   = "140129192647Z0A1" fullword
    $s13   = "ZBSystemInformation" fullword
    $s14   = "NetworkExtension" fullword
    $s15   = "JKArrayRemoveObjectAtIndex" fullword
    $s16   = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s17   = "AssemblyProductAttribute" fullword
    $s18   = "EqualizationPhase2" fullword
    $s19   = "CFBundleIdentifier" fullword
    $s20   = "KGCustButtonView" fullword
    $s21   = "IORegistryEntryCreateCFProperty" fullword
    $s23   = "terminationStatus" fullword
    $s24   = "systemScanPartialFixDone" fullword
    $s25   = "copyElephantBrain" fullword
    $s26   = "threadSafeMainBundle" fullword
    $s27   = "getMethodDescription" fullword
    $s28   = "ZBWebViewController" fullword
    $s29   = "20191105000000Z0" fullword
    $s30   = "CFBundleCopyBundleURL" fullword
    $s31   = "retainAutoreleaseReturnValue" fullword
    $s32   = "UHAWAVAUATSHHHuE" fullword
    $s33   = "HMHMHMHMHMHMHMHML" fullword
    $s34   = "isAppStoreDistribution" fullword
    $s35   = "isYahooSearchURL" fullword
    $s36   = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s37   = "140213191008Z0A1" fullword
    $s38   = "localizedStringForKey" fullword
    $s39   = "UHAWAVAUATSHhDMLpHMHUHuE" fullword
    $s40   = "didFailToRegisterForRemoteNotificationsWithError" fullword
    $s41   = "dictionaryWithContentsOfFile" fullword
    $s42   = "ZN9QListData11shared" fullword
    $s43   = "ApplicationServices" fullword
    $s45   = "HMHMHMHMHMHMHMHMHMH" fullword
    $s46   = "20160507105842Z0" fullword
    $s47   = "SystemConfiguration" fullword
    $s48   = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s49   = "HMHMHMHMHMHMHMHMH" fullword
    $s50   = "numberWithDouble" fullword
    $s51   = "PrivateFrameworks" fullword
    $s52   = "abcdefghijklmnopqrstuvwxyz" fullword
    $s53   = "FromStringAndSize" fullword
    $s54   = "e4zPO0A75QibEoIM1dS3ccGV3ag" fullword
    $s56   = "conformsToProtocol" fullword
    $s57   = "350209214036Z0b1" fullword
    $s58   = "libswiftDispatch" fullword
    $s59   = "NSAddressOfSymbol" fullword
    $s61   = "CFBundleShortVersionString" fullword
    $s62   = "replaceCharactersInRange" fullword
    $s63   = "respondsToSelector" fullword
    $s64   = "retainAutorelease" fullword
    $s65   = "dataWithContentsOfFile" fullword
    $s66   = "timeIntervalSinceDate" fullword
    $s67   = "stringByAppendingPathComponent" fullword
    $s70   = "setIsAccessibilityElement" fullword
    $s71   = "IOIteratorIsValid" fullword
    $s72   = "libswiftCoreGraphics" fullword
    $s73   = "autoreleaseReturnValue" fullword
    $s74   = "NSAutoreleasePool" fullword
    $s75   = "retainAutoreleasedReturnValue" fullword
    $s76   = "ServiceManagement" fullword
    $s79   = "CFReadStreamCreateWithFile" fullword
    $s80   = "DefaultRuneLocale" fullword
    $s81   = "UIViewController" fullword
    $s82   = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s83   = "OSAtomicDecrement32" fullword
    $s84   = "kCFAllocatorDefault" fullword
    $s85   = "dataUsingEncoding" fullword
    $s86   = "ZN9QListData7disposeEPNS" fullword
    $s87   = "UHAWAVAUATSPIIID" fullword
    $s88   = "intrinsicContentSize" fullword
    $s89   = "9allocatorIcEEEE" fullword
    $s90   = "CFConstantStringClassReference" fullword
    $s91   = "iPhoneSimulator10" fullword
    $s96   = "arrayWithObjects" fullword
    $s97   = "NSConcreteGlobalBlock" fullword
    $s141  = "addCleanerRemovedSize" fullword
    $s142  = "MacKeeperPrivilegedHelper" fullword
    $s143  = "210412223435Z0V1" fullword
    $s145  = "DEDEDEDEDEDEDEDE9E" fullword
    $s147  = "CFStringCreateWithCString" fullword
    $s149  = "debugDescription" fullword
    $s150  = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s151  = "IntermediateBuildFilesPath" fullword
    $s152  = "IOServiceGetMatchingServices" fullword
    $s154  = "UHAWAVAUATSPIHIH" fullword
    $s155  = "lswiftObjectiveC" fullword
    $s156  = "ddddddddddddddddddddddddddddddddsd" fullword
    $s157  = "initWithIdentifier" fullword
    $s159  = "UHAWAVAUATSH8HIH" fullword
    $s162  = "arrayWithCapacity" fullword
    $s164  = "getInstanceMethod" fullword
    $s165  = "objectForKeyedSubscript" fullword
    $s166  = "JSValueMakeBoolean" fullword
    $s169  = "HEHEHEHEHEHEHEHE" fullword
    $s170  = "createFileAtPath" fullword
    $s171  = "stringWithString" fullword
    $s173  = "0123456789abcdef" fullword
    $s175  = "CFStringGetCString" fullword
    $s177  = "ecpointformatlist" fullword
    $s178  = "libswiftCoreFoundation" fullword
    $s179  = "UHAWAVAUATSH8IIH" fullword
    $s182  = "UHAWAVAUATSPAAII" fullword
    $s184  = "NSNotificationCenter" fullword
    $s185  = "valueForProperty" fullword
    $s186  = "ZTSN5boost9exceptionE" fullword
    $s187  = "fileExistsAtPath" fullword
    $s188  = "UHAWAVAUATSH8IHH" fullword
    $s189  = "UserNotifications" fullword
    $s192  = "stringWithCapacity" fullword
    $s194  = "autoreleasePoolPop" fullword
    $s200  = "NSStringFromClass" fullword
    $s201  = "UHAWAVAUATSPIIHt" fullword
    $s285  = "countByEnumeratingWithState" fullword
    $s286  = "15mutex6unlockEv" fullword
    $s291  = "getInitializedObjCClass" fullword
    $s292  = "UBRARARARARARARARARARARARARARARARARARARBRB" fullword
    $s293  = "certificateauthority0" fullword
    $s295  = "getblocktemplate" fullword
    $s305  = "certificateauthority" fullword
    $s326  = "140305162647Z0A1" fullword
    $s348  = "responseSerializer" fullword
    $s352  = "NSAssertionHandler" fullword
    $s353  = "MobileCoreServices" fullword
    $s354  = "CFNumberGetValue" fullword
    $s357  = "stringWithFormat" fullword
    $s364  = "ImageCaptureCore" fullword
    $s388  = "CFDictionaryCreateMutable" fullword
    $s390  = "enumerationMutation" fullword
    $s407  = "SecStaticCodeCheckValidityWithErrors" fullword
    $s412  = "TZFE10FoundationSS36" fullword
    $s415  = "traitsIcEEE9showmanycEv" fullword
    $s416  = "AECreateAppleEvent" fullword
    $s418  = "ZN16QLoggingCategoryD1Ev" fullword
    $s419  = "191127221001Z0A1" fullword
    $s420  = "20191001103003Z0" fullword
    $s421  = "200219223002Z0B1" fullword
    $s422  = "getTupleTypeMetadata2" fullword
    $s424  = "CFBundleInfoDictionaryVersion" fullword
    $s429  = "NSFetchedPropertyDescription" fullword
    $s430  = "efCkKaADK3CAKRCNC" fullword
    $s431  = "270201221215Z0y1" fullword
    $s434  = "getExistentialTypeMetadata" fullword
    $s435  = "sharedApplication" fullword
    $s440  = "CFStringMakeConstantString" fullword
    $s443  = "ShCsSwSzfKpADKfADCNK" fullword
    $s465  = "191128154500Z0A1" fullword
    $s498  = "NSDistributedNotificationCenter" fullword
    $s513  = "scheduledTimerWithTimeInterval" fullword
    $s514  = "bundleIdentifier" fullword
    $s524  = "componentsSeparatedByString" fullword
    $s528  = "setMinimumContentSize" fullword
    $s565  = "CFURLGetFileSystemRepresentation" fullword
    $s585  = "completionHandler" fullword
    $s586  = "NSUndoManagerProxy" fullword
    $s591  = "RGp0SARARARARARA" fullword
    $s609  = "lengthOfBytesUsingEncoding" fullword
    $s620  = "GenerateConnectionID" fullword
    $s621  = "ZN2cv10AutoBufferIhLm4104EE8allocateEm" fullword
    $s622  = "k7kBkQkpkkkkkkkkkkflmllllll" fullword
    $s623  = "leftRightGridient" fullword
    $s624  = "fUHAWAVSPIHIIv0Ht" fullword
    $s625  = "ZTIN10CryptoNote24JsonInputValueSerializerE" fullword
    $s626  = "UHAWAVAUATSHxMLEUuAH" fullword
    $s627  = "errcallEPPFvPK5DbEnvPKcS4" fullword
    $s629  = "isLifetimeEnabled" fullword
    $s630  = "ponponqqtsrtsruuxwvwvyy" fullword
    $s631  = "LSGetCurrentApplicationASN" fullword
    $s632  = "N4laya11JSCFunctionIPFlllbEEE" fullword
    $s633  = "lockScreenAuthenticationDidFailWithAttempt" fullword
    $s634  = "ZTVN5xmrig18SinglePoolStrategyE" fullword
    $s635  = "introductionView" fullword
    $s638  = "CFURLCopyFileSystemPath" fullword
    $s639  = "applicationShouldHandleReopen" fullword
    $s640  = "DRGp0SARARARARARA" fullword
    $s641  = "UHAWAVAUATSPIIAAHtJH" fullword
    $s642  = "kMDItemWhereFroms" fullword
    $s643  = "NSOperationQueue" fullword
    $s644  = "numberWithUnsignedInt" fullword
    $s646  = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s648  = "fileHandleForReading" fullword
    $s649  = "shouldDragDocumentWithEvent" fullword
    $s650  = "runningApplications" fullword
    $s651  = "SleepNotificationMBS" fullword
    $s653  = "operatingSystemVersionString" fullword
    $s656  = "enumerateKeysAndObjectsUsingBlock" fullword
    $s657  = "registerForMessageName" fullword
    $s666  = "NSJSONSerialization" fullword
    $s670  = "ellipticcurvelist" fullword
    $s671  = "alSourceQueueBuffers" fullword
    $s675  = "ZN9QListData6appendERKS" fullword
    $s676  = "dictionaryWithJSONString" fullword
    $s677  = "stringWithUTF8String" fullword
    $s678  = "caseInsensitiveCompare" fullword
    $s682  = "getImplementation" fullword
    $s709  = "9allocatorIcEEEC1ERKS5" fullword
    $s716  = "CGPathCreateMutable" fullword
    $s719  = "redirectResponse" fullword
    $s724  = "NSStringPboardType" fullword
    $s729  = "9allocatorIcEEE6insertEmPKcm" fullword
    $s733  = "UHAWAVAUATSH8IIHH" fullword
    $s734  = "ZN7QLayout18setContentsMarginsEiiii" fullword
    $s736  = "UHAWAVAUATSPAIIB" fullword
    $s741  = "DisableThreadLibraryCalls" fullword
    $s742  = "traitsIcEEE3putEc" fullword
    $s812  = "glFramebufferTextureLayer" fullword
    $s813  = "componentsJoinedByString" fullword
    $s818  = "N5boost9exceptionE" fullword
    $s821  = "GetDiskFreeSpace" fullword
    $s828  = "CFArrayGetValueAtIndex" fullword
    $s841  = "StringCharCodeAt" fullword
    $s864  = "fHSUATAUAVIHHIHIHD" fullword
    $s890  = "encodeURIComponent" fullword
    $s891  = "UHAWAVAUATSPIHIIH" fullword
    $s895  = "E6targetERKSt9type" fullword
    $s896  = "IOPlatformExpertDevice" fullword
    $s926  = "numberWithUnsignedLong" fullword
    $s927  = "initWithCapacity" fullword
    $s929  = "setHTTPShouldHandleCookies" fullword
    $s933  = "NSFilenamesPboardType" fullword
    $s934  = "NSPropertyListSerialization" fullword
    $s947  = "replaceObjectAtIndex" fullword
    $s972  = "AudioConverterGetProperty" fullword
    $s978  = "CFBundleGetVersionNumber" fullword
    $s979  = "applicationState" fullword
    $s981  = "CGContextRelease" fullword
    $s987  = "N5boost6detail11thread" fullword
    $s989  = "SecTransformExecute" fullword
    $s999  = "objectAtIndexedSubscript" fullword
    $s1006 = "IOCreatePlugInInterfaceForService" fullword
    $s1007 = "crossCertificatePair" fullword
    $s1009 = "UHAWAVAUATSHhMMIH" fullword
    $s1078 = "withIntermediateDirectories" fullword
    $s1080 = "substringToIndex" fullword
    $s1088 = "numberWithUnsignedInteger" fullword
    $s1090 = "removeObjectForKey" fullword
    $s1092 = "columnIndexForName" fullword
    $s1116 = "cancelAllOperations" fullword
    $s1156 = "CGRectContainsPoint" fullword
    $s1157 = "dataWithJSONObject" fullword
    $s1169 = "insertStatisticEvent" fullword
    $s1171 = "deletedMethodError" fullword
    $s1183 = "mediumspringgreen" fullword
    $s1200 = "bridgeToObjectiveCSo5NSURLCyF" fullword
    $s1207 = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s1211 = "didEndDisplayingHeaderView" fullword
    $s1216 = "CGImageSourceGetCount" fullword
    $s1230 = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s1244 = "systemFontOfSize" fullword
    $s1245 = "kZBZeoAccountLoggedInNotification" fullword
    $s1262 = "setButton1Action" fullword
    $s1266 = "ZBUSystemInformation" fullword
    $s1269 = "contentsOfDirectoryAtPath" fullword
    $s1270 = "componentsSeparatedByCharactersInSet" fullword
    $s1273 = "AuthorizationFree" fullword
    $s1283 = "allocatorI11FILE" fullword
    $s1285 = "agentDidFinishValidateItem" fullword
    $s1289 = "includingPropertiesForKeys" fullword
    $s1300 = "NSRunningApplication" fullword
    $s1307 = "viewForTableColumn" fullword
    $s1308 = "backingScaleFactor" fullword
    $s1309 = "executeWithPrivileges" fullword
    $s1321 = "ARCLiteIndexedSubscripting" fullword
    $s1334 = "addScriptMessageHandler" fullword
    $s1335 = "createDirectoryAtURL" fullword
    $s1339 = "enumerateObjectsUsingBlock" fullword
    $s1347 = "34CachingTransactionSignatureChecker" fullword
    $s1348 = "initializeClassPair" fullword
    $s1349 = "ZTI15CCoinsViewCache" fullword
    $s1358 = "ZN5xmrig6OclLib18getProgramBuildLogEP11" fullword
    $s1359 = "9allocatorIyEEEES4" fullword
    $s1361 = "ZN6Common9JsonValue3setERKNSt3" fullword
    $s1363 = "bQHbQHbQHbQHbqHbHbQHbHbQHbQHb" fullword
    $s1365 = "traitsIcEEEEE16find" fullword
    $s1390 = "G16ComparisonResultOtF" fullword
    $s1392 = "setScanResultCategory" fullword
    $s1393 = "UIAlertViewDelegate" fullword
    $s1395 = "NSAccessibilityValueChangedNotification" fullword
    $s1397 = "isExecutableFileAtPath" fullword
    $s1400 = "NSMutableOrderedSet" fullword
    $s1401 = "conformsToProtocolEPKNS" fullword
    $s1406 = "UIModalPresentationOverCurrentContext" fullword
    $s1413 = "initWithSuiteName" fullword
    $s1422 = "replacementString" fullword
    $s1424 = "delegateHandlesKey" fullword
    $s1437 = "invalidateShadow" fullword
    $s1448 = "applicationWillHide" fullword
    $s1456 = "willEncodeRestorableStateWithCoder" fullword
    $s1457 = "preDownloadAssets" fullword
    $s1474 = "DispatchOnceCounter" fullword
    $s1483 = "loadWeakRetained" fullword
    $s1494 = "timerWithTimeInterval" fullword
    $s1496 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1509 = "collectingEnabled" fullword
    $s1514 = "CFBundleExecutable" fullword
    $s1522 = "NSLayoutConstraint" fullword
    $s1530 = "CGContextFillPath" fullword
    $s1533 = "connectionRequired" fullword
    $s1535 = "didFinishDownloadingToURL" fullword
    $s1539 = "CFRunLoopGetMain" fullword
    $s1541 = "IOConnectCallAsyncMethod" fullword
    $s1544 = "dataAttributeWithTag" fullword
    $s1547 = "NSURLSessionDataTask" fullword
    $s1566 = "createDragButtons" fullword
    $s1571 = "systemVersionString" fullword
    $s1586 = "hEPONPONSRQRTT62" fullword
    $s1588 = "EXUa2Kc9Qd9ysfHNqqIFg" fullword
    $s1597 = "clickedButtonAtIndex" fullword
    $s1598 = "textFieldDidEndEditing" fullword
    $s1604 = "seekToFileOffset" fullword
    $s1614 = "performActionForShortcutItem" fullword
    $s1625 = "CGContextFillRect" fullword
    $s1631 = "113EmptyIterator4SeekERKNS" fullword
    $s1632 = "10ConfigDataEE3Arg11hasLongNameERKNSt3" fullword
    $s1633 = "ZN5boost19thread" fullword
    $s1634 = "NSUserNotificationCenterDelegate" fullword
    $s1636 = "ZNK5boost3any6holderImE4typeEv" fullword
    $s1641 = "ZNK5boost6spirit7classic4impl16real" fullword
    $s1651 = "ZN11WalletModel20getAddressTableModelEv" fullword
    $s1658 = "ZN10cryptonote21is" fullword
    $s1661 = "NSAppleEventManager" fullword
    $s1668 = "formatsIcE27duration" fullword
    $s1669 = "113EmptyIteratorE" fullword
    $s1672 = "9allocatorIcEEEEPNS0" fullword
    $s1688 = "registerClassPair" fullword
    $s1689 = "selectorPFP11objc" fullword
    $s1690 = "ZL30NSUndoManagerProxy" fullword
    $s1706 = "checkForUpdatesInBackground" fullword
    $s1711 = "NSSharingServicePicker" fullword
    $s1712 = "UHAWAVAUATSHXMHH" fullword
    $s1714 = "CFBundleCopyResourceURL" fullword
    $s1715 = "appropriateForDirectoryURL" fullword
    $s1719 = "characterIsMember" fullword
    $s1721 = "autoreleasePoolPushv" fullword
    $s1723 = "kSecAttrAccessGroup" fullword
    $s1730 = "JcBX2ZiyBahx4RJr4gGw3WIOY" fullword
    $s1734 = "dataTaskWithRequest" fullword
    $s1738 = "setAllowedFileTypes" fullword
    $s1764 = "imageWithCGImage" fullword
    $s1785 = "defaultConfiguration" fullword
    $s1791 = "applicationDidResignActive" fullword
    $s1803 = "s10Foundation3URLV19" fullword
    $s1830 = "otherButtonTitles" fullword
    $s1848 = "autoreleasepoolPK11mach" fullword
    $s1866 = "URLSessionDidFinishEventsForBackgroundURLSession" fullword
    $s1870 = "initWithContentsOfURL" fullword
    $s1872 = "127clEvE15obfuscated" fullword
    $s1873 = "unzGoToFilePos64" fullword
    $s1882 = "connectionDidFinishLoading" fullword
    $s1900 = "fileManagerByPreservingAuthorizationRights" fullword
    $s1906 = "setAttributedTitle" fullword
    $s1908 = "convertObjCBoolToBoolFVS" fullword
    $s1931 = "fkzienviptjqzaavumcectmwezot" fullword
    $s1935 = "NSMutableURLRequest" fullword
    $s1942 = "kSecAttrAuthenticationTypeDPA" fullword

  condition:
    ((#s0 <= 0.5)
      and ((#s1 <= 0.5)
        and ((#s2 <= 0.5)
          and ((#s3 <= 0.5)
            and ((#s4 <= 0.5)
              and ((#s5 <= 0.5)
                and ((#s6 <= 1.0)
                  and ((#s7 <= 1.0)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 0.5)
                        and ((#s10 <= 0.5)
                          and ((#s11 <= 0.5)
                            and ((#s12 <= 0.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 1.5)
                                  and ((#s15 <= 0.5)
                                    and ((#s16 <= 0.5)
                                      and ((#s17 <= 0.5)
                                        and ((#s18 <= 0.5)
                                          and ((#s19 <= 0.5)
                                            and ((#s20 <= 0.5)
                                              and ((#s21 <= 1.5)
                                                and ((filesize <= 69604.0)
                                                  and ((#s23 <= 0.5)
                                                    and ((#s24 <= 0.5)
                                                      and ((#s25 <= 1.5)
                                                        and ((#s26 <= 0.5)
                                                          and ((#s27 <= 0.5)
                                                            and ((#s28 <= 0.5)
                                                              and ((#s29 <= 0.5)
                                                                and ((#s30 <= 1.5)
                                                                  and ((#s31 <= 0.5)
                                                                    and ((#s32 <= 0.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s34 <= 0.5)
                                                                          and ((#s35 <= 1.0)
                                                                            and ((#s36 <= 0.5)
                                                                              and ((#s37 <= 0.5)
                                                                                and ((#s38 <= 0.5)
                                                                                  and ((#s39 <= 0.5)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((filesize <= 49950.0)
                                                                                              and ((#s45 <= 0.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 1.5)
                                                                                                    and ((#s48 <= 0.5)
                                                                                                      and ((#s49 <= 0.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 0.5)
                                                                                                            and ((#s52 <= 0.5)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((#s54 <= 0.5)
                                                                                                                  and ((filesize <= 16468.0)
                                                                                                                    and ((#s56 <= 0.5)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s47 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 0.5)
                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s66 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((filesize > 4222.0)
                                                                                                                                              and ((#s70 <= 0.5)
                                                                                                                                                and ((#s71 <= 1.0)
                                                                                                                                                  and ((#s72 <= 0.5)
                                                                                                                                                    and ((#s73 <= 0.5)
                                                                                                                                                      and ((#s74 <= 1.0)
                                                                                                                                                        and ((#s75 <= 0.5)
                                                                                                                                                          and ((#s76 <= 3.0)
                                                                                                                                                            and ((filesize > 4236.0)
                                                                                                                                                              and ((#s79 <= 0.5)
                                                                                                                                                                and ((#s80 <= 0.5)
                                                                                                                                                                  and ((#s81 <= 1.5)
                                                                                                                                                                    and ((#s82 <= 0.5)
                                                                                                                                                                      and ((#s83 <= 0.5)
                                                                                                                                                                        and ((#s84 <= 0.5)
                                                                                                                                                                          and ((#s85 <= 0.5)
                                                                                                                                                                            and ((#s86 <= 0.5)
                                                                                                                                                                              and ((#s87 <= 0.5)
                                                                                                                                                                                and ((#s88 <= 2.0)
                                                                                                                                                                                  and ((#s89 <= 1.0)
                                                                                                                                                                                    and ((#s90 <= 0.5)
                                                                                                                                                                                      and ((#s91 <= 1.5)
                                                                                                                                                                                        and ((filesize <= 5196.0)
                                                                                                                                                                                          and ((filesize > 5152.0)
                                                                                                                                                                                          ) or (filesize > 5196.0)
                                                                                                                                                                                          and ((#s96 <= 0.5)
                                                                                                                                                                                            and ((#s97 <= 0.5)
                                                                                                                                                                                              and ((filesize <= 12530.0)
                                                                                                                                                                                                and ((filesize > 8946.0)
                                                                                                                                                                                                  and ((filesize <= 8962.0)
                                                                                                                                                                                                  )) or (filesize > 12530.0)
                                                                                                                                                                                                and ((filesize <= 12558.0)
                                                                                                                                                                                                ))))))))))))))))))))))))))))))))))))))) or (filesize > 16468.0)
                                                                                                                    and ((#s141 <= 0.5)
                                                                                                                      and ((#s142 <= 1.0)
                                                                                                                        and ((#s143 <= 0.5)
                                                                                                                          and ((#s91 <= 0.5)
                                                                                                                            and ((#s145 <= 0.5)
                                                                                                                              and ((#s57 <= 0.5)
                                                                                                                                and ((#s147 <= 0.5)
                                                                                                                                  and ((#s59 <= 0.5)
                                                                                                                                    and ((#s149 <= 1.0)
                                                                                                                                      and ((#s150 <= 0.5)
                                                                                                                                        and ((#s151 <= 0.5)
                                                                                                                                          and ((#s152 <= 0.5)
                                                                                                                                            and ((#s73 <= 0.5)
                                                                                                                                              and ((#s154 <= 0.5)
                                                                                                                                                and ((#s155 <= 0.5)
                                                                                                                                                  and ((#s156 <= 0.5)
                                                                                                                                                    and ((#s157 <= 0.5)
                                                                                                                                                      and ((#s67 <= 0.5)
                                                                                                                                                        and ((#s159 <= 0.5)
                                                                                                                                                          and ((#s85 <= 0.5)
                                                                                                                                                            and ((#s89 <= 0.5)
                                                                                                                                                              and ((#s162 <= 0.5)
                                                                                                                                                                and ((#s82 <= 0.5)
                                                                                                                                                                  and ((#s164 <= 0.5)
                                                                                                                                                                    and ((#s165 <= 0.5)
                                                                                                                                                                      and ((#s166 <= 1.5)
                                                                                                                                                                        and ((filesize <= 16494.0)
                                                                                                                                                                          or (filesize > 16494.0)
                                                                                                                                                                          and ((#s169 <= 0.5)
                                                                                                                                                                            and ((#s170 <= 0.5)
                                                                                                                                                                              and ((#s171 <= 0.5)
                                                                                                                                                                                and ((#s63 <= 0.5)
                                                                                                                                                                                  and ((#s173 <= 0.5)
                                                                                                                                                                                    and ((#s74 <= 1.0)
                                                                                                                                                                                      and ((#s175 <= 0.5)
                                                                                                                                                                                        and ((#s96 <= 0.5)
                                                                                                                                                                                          and ((#s177 <= 1.0)
                                                                                                                                                                                            and ((#s178 <= 0.5)
                                                                                                                                                                                              and ((#s179 <= 0.5)
                                                                                                                                                                                                and ((#s84 <= 2.0)
                                                                                                                                                                                                  and ((#s62 <= 0.5)
                                                                                                                                                                                                    and ((#s182 <= 0.5)
                                                                                                                                                                                                      and ((#s90 <= 0.5)
                                                                                                                                                                                                        and ((#s184 <= 1.0)
                                                                                                                                                                                                          and ((#s185 <= 0.5)
                                                                                                                                                                                                            and ((#s186 <= 0.5)
                                                                                                                                                                                                              and ((#s187 <= 0.5)
                                                                                                                                                                                                                and ((#s188 <= 0.5)
                                                                                                                                                                                                                  and ((#s189 <= 1.0)
                                                                                                                                                                                                                    and ((#s58 <= 0.5)
                                                                                                                                                                                                                      and ((#s75 <= 0.5)
                                                                                                                                                                                                                        and ((#s192 <= 0.5)
                                                                                                                                                                                                                          and ((#s81 <= 0.5)
                                                                                                                                                                                                                            and ((#s194 <= 1.5)
                                                                                                                                                                                                                              and ((#s80 <= 0.5)
                                                                                                                                                                                                                                and ((#s76 <= 1.0)
                                                                                                                                                                                                                                  and ((#s97 <= 0.5)
                                                                                                                                                                                                                                    and ((filesize <= 26134.0)
                                                                                                                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                                                                                                                        and ((#s200 <= 0.5)
                                                                                                                                                                                                                                          and ((#s201 <= 0.5)
                                                                                                                                                                                                                                            and ((filesize <= 26048.0)
                                                                                                                                                                                                                                              and ((filesize <= 20788.0)
                                                                                                                                                                                                                                                and ((filesize > 18966.0)
                                                                                                                                                                                                                                                  and ((filesize <= 19022.0)
                                                                                                                                                                                                                                                  )) or (filesize > 20788.0)
                                                                                                                                                                                                                                                and ((filesize <= 20818.5)
                                                                                                                                                                                                                                                  or (filesize > 20818.5)
                                                                                                                                                                                                                                                  and ((filesize <= 25072.0)
                                                                                                                                                                                                                                                    and ((filesize <= 21326.0)
                                                                                                                                                                                                                                                      and ((filesize > 21250.0)
                                                                                                                                                                                                                                                      )) or (filesize > 25072.0)
                                                                                                                                                                                                                                                    and ((filesize <= 25284.0)
                                                                                                                                                                                                                                                      and ((filesize <= 25140.0)
                                                                                                                                                                                                                                                        and ((filesize <= 25116.0)
                                                                                                                                                                                                                                                        ) or (filesize > 25140.0)
                                                                                                                                                                                                                                                      ))))) or (filesize > 26048.0)
                                                                                                                                                                                                                                            )))) or (filesize > 26134.0)
                                                                                                                                                                                                                                      and ((filesize > 38242.0)
                                                                                                                                                                                                                                        and ((filesize <= 38360.0)
                                                                                                                                                                                                                                        ))))))))))))))))))))))))))) or (#s173 > 0.5)
                                                                                                                                                                                  )))) or (#s169 > 0.5)
                                                                                                                                                                          )))))))))))) or (#s156 > 0.5)
                                                                                                                                                  )))))) or (#s150 > 0.5)
                                                                                                                                        and ((filesize <= 25456.0)
                                                                                                                                        ))))) or (#s57 > 0.5)
                                                                                                                                and ((#s80 <= 1.5)
                                                                                                                                  and ((#s285 <= 0.5)
                                                                                                                                    and ((#s286 <= 1.0)
                                                                                                                                      and ((#s57 > 1.5)
                                                                                                                                        and ((#s61 <= 0.5)
                                                                                                                                          and ((#s84 <= 0.5)
                                                                                                                                            and ((#s291 <= 1.0)
                                                                                                                                              and ((#s292 <= 0.5)
                                                                                                                                                and ((#s293 <= 0.5)
                                                                                                                                                  and ((#s76 <= 1.0)
                                                                                                                                                    and ((#s295 <= 0.5)
                                                                                                                                                      and ((#s175 <= 1.0)
                                                                                                                                                        and ((#s194 <= 1.0)
                                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                                            and ((#s182 <= 0.5)
                                                                                                                                                              and ((#s179 <= 0.5)
                                                                                                                                                                and ((#s89 <= 17.0)
                                                                                                                                                                  and ((#s152 <= 2.0)
                                                                                                                                                                    and ((filesize <= 27272.0)
                                                                                                                                                                      and ((#s90 <= 1.0)
                                                                                                                                                                        and ((#s305 > 0.5)
                                                                                                                                                                        )))))))))) or (#s295 > 0.5)
                                                                                                                                                    )))))))))) or (#s80 > 1.5)
                                                                                                                                  and ((#s326 > 0.5)
                                                                                                                                  ))) or (#s145 > 0.5)
                                                                                                                            ))) or (#s142 > 1.0)
                                                                                                                      ) or (#s141 > 0.5)
                                                                                                                    )) or (#s54 > 0.5)
                                                                                                                )) or (#s52 > 0.5)
                                                                                                              and ((#s52 <= 1.5)
                                                                                                                and ((filesize > 27692.0)
                                                                                                                ))))) or (#s49 > 0.5)
                                                                                                      ) or (#s48 > 0.5)
                                                                                                    ) or (#s47 > 1.5)
                                                                                                    and ((#s305 <= 0.5)
                                                                                                      and ((#s56 <= 0.5)
                                                                                                        and ((#s143 <= 0.5)
                                                                                                          and ((#s348 <= 0.5)
                                                                                                            and ((#s64 <= 0.5)
                                                                                                              and ((#s51 <= 0.5)
                                                                                                                and ((#s89 <= 5.0)
                                                                                                                  and ((#s352 <= 0.5)
                                                                                                                    and ((#s353 <= 2.5)
                                                                                                                      and ((#s354 <= 0.5)
                                                                                                                        and ((#s91 <= 8.0)
                                                                                                                          and ((#s72 <= 0.5)
                                                                                                                            and ((#s357 <= 0.5)
                                                                                                                              and ((filesize <= 19830.0)
                                                                                                                                and ((#s293 <= 0.5)
                                                                                                                                  and ((#s57 <= 1.0)
                                                                                                                                    and ((#s189 <= 1.0)
                                                                                                                                      and ((#s155 <= 0.5)
                                                                                                                                        and ((#s73 <= 0.5)
                                                                                                                                          and ((#s364 <= 1.0)
                                                                                                                                            and ((filesize > 19296.0)
                                                                                                                                            )))) or (#s189 > 1.0)
                                                                                                                                      and ((filesize > 8760.0)
                                                                                                                                        and ((filesize <= 12452.0)
                                                                                                                                          or (filesize > 12452.0)
                                                                                                                                          and ((#s353 > 1.0)
                                                                                                                                          )))))))))))))) or (#s51 > 0.5)
                                                                                                                and ((#s388 <= 0.5)
                                                                                                                  and ((#s353 <= 1.0)
                                                                                                                    and ((#s390 <= 1.0)
                                                                                                                      and ((#s189 > 1.0)
                                                                                                                      ))))))))))) or (#s46 > 0.5)
                                                                                                ) or (#s45 > 0.5)
                                                                                              ) or (filesize > 49950.0)
                                                                                              and ((#s59 <= 0.5)
                                                                                                and ((#s390 <= 0.5)
                                                                                                  and ((#s189 <= 0.5)
                                                                                                    and ((#s407 <= 1.0)
                                                                                                      and ((#s154 <= 0.5)
                                                                                                        and ((#s75 <= 0.5)
                                                                                                          and ((#s84 <= 0.5)
                                                                                                            and ((#s90 <= 0.5)
                                                                                                              and ((#s412 <= 0.5)
                                                                                                                and ((#s182 <= 0.5)
                                                                                                                  and ((#s170 <= 0.5)
                                                                                                                    and ((#s415 <= 0.5)
                                                                                                                      and ((#s416 <= 0.5)
                                                                                                                        and ((#s97 <= 0.5)
                                                                                                                          and ((#s418 <= 1.0)
                                                                                                                            and ((#s419 <= 0.5)
                                                                                                                              and ((#s420 <= 0.5)
                                                                                                                                and ((#s421 <= 0.5)
                                                                                                                                  and ((#s422 <= 0.5)
                                                                                                                                    and ((#s293 <= 0.5)
                                                                                                                                      and ((#s424 <= 0.5)
                                                                                                                                        and ((#s152 <= 1.0)
                                                                                                                                          and ((#s51 <= 1.0)
                                                                                                                                            and ((#s49 <= 0.5)
                                                                                                                                              and ((#s53 <= 0.5)
                                                                                                                                                and ((#s429 <= 1.0)
                                                                                                                                                  and ((#s430 <= 0.5)
                                                                                                                                                    and ((#s431 <= 0.5)
                                                                                                                                                      and ((#s73 <= 0.5)
                                                                                                                                                        and ((#s57 <= 0.5)
                                                                                                                                                          and ((#s434 <= 1.0)
                                                                                                                                                            and ((#s435 <= 0.5)
                                                                                                                                                              and ((#s58 <= 0.5)
                                                                                                                                                                and ((#s76 <= 1.0)
                                                                                                                                                                  and ((#s74 <= 1.0)
                                                                                                                                                                    and ((#s291 <= 0.5)
                                                                                                                                                                      and ((#s440 <= 0.5)
                                                                                                                                                                        and ((#s89 <= 1.0)
                                                                                                                                                                          and ((filesize <= 50250.0)
                                                                                                                                                                            and ((#s443 <= 0.5)
                                                                                                                                                                              and ((filesize <= 50174.5)
                                                                                                                                                                                or (filesize > 50174.5)
                                                                                                                                                                                and ((filesize > 50178.5)
                                                                                                                                                                                )) or (#s443 > 0.5)
                                                                                                                                                                            )))))))))))) or (#s431 > 0.5)
                                                                                                                                                      and ((#s57 > 1.5)
                                                                                                                                                        and ((#s80 <= 1.0)
                                                                                                                                                          and ((#s431 <= 1.5)
                                                                                                                                                            and ((#s465 <= 0.5)
                                                                                                                                                              and ((#s82 <= 1.0)
                                                                                                                                                                and ((filesize > 68013.0)
                                                                                                                                                                  and ((#s305 > 0.5)
                                                                                                                                                                  ))) or (#s465 > 0.5)
                                                                                                                                                              and ((#s305 > 0.5)
                                                                                                                                                              )))))) or (#s430 > 0.5)
                                                                                                                                                  )))))))))) or (#s420 > 0.5)
                                                                                                                              ))))))))) or (#s90 > 0.5)
                                                                                                              and ((#s175 <= 0.5)
                                                                                                                and ((#s498 <= 1.0)
                                                                                                                  and ((#s51 > 0.5)
                                                                                                                    and ((#s51 <= 2.5)
                                                                                                                    ))))))))))))) or (#s43 > 0.5)
                                                                                            and ((#s513 <= 0.5)
                                                                                              and ((#s514 > 0.5)
                                                                                              ))))) or (#s40 > 0.5)
                                                                                      and ((#s96 > 0.5)
                                                                                      )) or (#s39 > 0.5)
                                                                                  ) or (#s38 > 0.5)
                                                                                  and ((#s524 <= 0.5)
                                                                                    and ((#s194 <= 1.0)
                                                                                      and ((#s390 > 0.5)
                                                                                        and ((#s528 > 0.5)
                                                                                        )) or (#s194 > 1.0)
                                                                                      and ((#s96 <= 1.0)
                                                                                        and ((#s431 > 0.5)
                                                                                        ))) or (#s524 > 0.5)
                                                                                    and ((#s90 > 1.5)
                                                                                      and ((#s51 <= 0.5)
                                                                                        and ((filesize > 28994.0)
                                                                                        ))))) or (#s37 > 0.5)
                                                                                and ((#s293 <= 0.5)
                                                                                ))) or (#s35 > 1.0)
                                                                          ) or (#s34 > 0.5)
                                                                        ) or (#s33 > 0.5)
                                                                      ) or (#s32 > 0.5)
                                                                    ) or (#s31 > 0.5)
                                                                    and ((#s524 <= 0.5)
                                                                      and ((#s431 > 0.5)
                                                                        and ((#s63 <= 0.5)
                                                                          and ((#s357 <= 0.5)
                                                                          ))))) or (#s30 > 1.5)
                                                                  and ((#s354 <= 1.0)
                                                                    and ((#s47 <= 1.5)
                                                                      and ((#s57 > 0.5)
                                                                        and ((#s293 <= 0.5)
                                                                          and ((#s565 <= 2.5)
                                                                            and ((#s175 <= 0.5)
                                                                              and ((filesize <= 19912.0)
                                                                              ) or (#s175 > 0.5)
                                                                              and ((filesize <= 20408.0)
                                                                              )) or (#s565 > 2.5)
                                                                          )))))) or (#s29 > 0.5)
                                                              ) or (#s28 > 0.5)
                                                            ) or (#s27 > 0.5)
                                                            and ((#s65 <= 0.5)
                                                              and ((#s85 <= 0.5)
                                                                and ((#s164 <= 0.5)
                                                                  or (#s164 > 0.5)
                                                                  and ((#s357 <= 0.5)
                                                                    and ((#s165 <= 1.5)
                                                                      and ((#s585 <= 0.5)
                                                                        and ((#s586 > 0.5)
                                                                          and ((filesize <= 61708.0)
                                                                            and ((#s75 <= 2.0)
                                                                              and ((#s43 <= 1.0)
                                                                                and ((#s591 > 0.5)
                                                                                ))) or (filesize > 61708.0)
                                                                            and ((#s73 > 2.0)
                                                                            ))))) or (#s357 > 0.5)
                                                                    and ((#s67 > 0.5)
                                                                    ))) or (#s85 > 0.5)
                                                              ))) or (#s26 > 0.5)
                                                        ) or (#s25 > 1.5)
                                                      ) or (#s24 > 0.5)
                                                    ) or (#s23 > 0.5)
                                                    and ((#s609 <= 0.5)
                                                      and ((#s57 > 0.5)
                                                        and ((#s23 <= 1.5)
                                                          and ((#s524 <= 0.5)
                                                            and ((#s149 <= 0.5)
                                                            )) or (#s23 > 1.5)
                                                        )))) or (filesize > 69604.0)
                                                  and ((#s620 <= 1.0)
                                                    and ((#s621 <= 2.0)
                                                      and ((#s622 <= 0.5)
                                                        and ((#s623 <= 0.5)
                                                          and ((#s624 <= 0.5)
                                                            and ((#s625 <= 0.5)
                                                              and ((#s626 <= 0.5)
                                                                and ((#s627 <= 0.5)
                                                                  and ((#s295 <= 1.0)
                                                                    and ((#s629 <= 0.5)
                                                                      and ((#s630 <= 1.0)
                                                                        and ((#s631 <= 0.5)
                                                                          and ((#s632 <= 0.5)
                                                                            and ((#s633 <= 0.5)
                                                                              and ((#s634 <= 0.5)
                                                                                and ((#s635 <= 0.5)
                                                                                  and ((#s147 <= 0.5)
                                                                                    and ((#s513 <= 4.0)
                                                                                      and ((#s638 <= 1.5)
                                                                                        and ((#s639 <= 2.5)
                                                                                          and ((#s640 <= 0.5)
                                                                                            and ((#s641 <= 0.5)
                                                                                              and ((#s642 <= 0.5)
                                                                                                and ((#s643 <= 0.5)
                                                                                                  and ((#s644 <= 1.5)
                                                                                                    and ((#s75 <= 0.5)
                                                                                                      and ((#s646 <= 0.5)
                                                                                                        and ((#s431 <= 0.5)
                                                                                                          and ((#s648 <= 0.5)
                                                                                                            and ((#s649 <= 0.5)
                                                                                                              and ((#s650 <= 0.5)
                                                                                                                and ((#s651 <= 2.0)
                                                                                                                  and ((#s415 <= 0.5)
                                                                                                                    and ((#s653 <= 0.5)
                                                                                                                      and ((#s74 <= 0.5)
                                                                                                                        and ((#s418 <= 1.0)
                                                                                                                          and ((#s656 <= 0.5)
                                                                                                                            and ((#s657 <= 1.0)
                                                                                                                              and ((#s173 <= 0.5)
                                                                                                                                and ((#s434 <= 1.0)
                                                                                                                                  and ((#s59 <= 0.5)
                                                                                                                                    and ((filesize <= 457316.0)
                                                                                                                                      and ((#s96 <= 0.5)
                                                                                                                                        and ((#s84 <= 0.5)
                                                                                                                                          and ((#s47 <= 0.5)
                                                                                                                                            and ((filesize <= 170316.0)
                                                                                                                                              and ((#s666 <= 1.0)
                                                                                                                                                and ((#s82 <= 1.0)
                                                                                                                                                  and ((#s57 <= 0.5)
                                                                                                                                                    and ((#s390 <= 0.5)
                                                                                                                                                      and ((#s670 <= 1.0)
                                                                                                                                                        and ((#s671 <= 1.0)
                                                                                                                                                          and ((#s72 <= 0.5)
                                                                                                                                                            and ((#s524 <= 0.5)
                                                                                                                                                              and ((#s192 <= 1.0)
                                                                                                                                                                and ((#s675 <= 0.5)
                                                                                                                                                                  and ((#s676 <= 0.5)
                                                                                                                                                                    and ((#s677 <= 0.5)
                                                                                                                                                                      and ((#s678 <= 0.5)
                                                                                                                                                                        and ((#s90 <= 0.5)
                                                                                                                                                                          and ((#s91 <= 1.0)
                                                                                                                                                                            and ((filesize <= 71394.0)
                                                                                                                                                                              and ((#s682 <= 0.5)
                                                                                                                                                                                and ((#s43 <= 1.0)
                                                                                                                                                                                  and ((filesize > 71036.0)
                                                                                                                                                                                    and ((filesize <= 71180.0)
                                                                                                                                                                                      or (filesize > 71180.0)
                                                                                                                                                                                      and ((filesize > 71220.0)
                                                                                                                                                                                      ))))))))))))))))))))) or (filesize > 170316.0)
                                                                                                                                              and ((#s709 <= 1.0)
                                                                                                                                                and ((#s682 <= 0.5)
                                                                                                                                                  and ((#s585 <= 0.5)
                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                      and ((#s188 <= 0.5)
                                                                                                                                                        and ((#s36 <= 1.0)
                                                                                                                                                          and ((#s51 <= 2.0)
                                                                                                                                                            and ((#s716 <= 0.5)
                                                                                                                                                              and ((#s143 <= 0.5)
                                                                                                                                                                and ((#s150 <= 0.5)
                                                                                                                                                                  and ((#s719 <= 2.0)
                                                                                                                                                                    and ((#s154 <= 0.5)
                                                                                                                                                                      and ((#s56 <= 0.5)
                                                                                                                                                                        and ((#s293 <= 0.5)
                                                                                                                                                                          and ((#s52 <= 0.5)
                                                                                                                                                                            and ((#s724 <= 0.5)
                                                                                                                                                                              and ((#s81 <= 0.5)
                                                                                                                                                                                and ((#s43 <= 1.0)
                                                                                                                                                                                  and ((#s182 <= 0.5)
                                                                                                                                                                                    and ((#s286 <= 0.5)
                                                                                                                                                                                      and ((#s729 <= 0.5)
                                                                                                                                                                                        and ((#s87 <= 0.5)
                                                                                                                                                                                          and ((#s57 <= 0.5)
                                                                                                                                                                                            and ((#s390 <= 0.5)
                                                                                                                                                                                              and ((#s733 <= 0.5)
                                                                                                                                                                                                and ((#s734 <= 1.0)
                                                                                                                                                                                                  and ((#s179 <= 0.5)
                                                                                                                                                                                                    and ((#s736 <= 0.5)
                                                                                                                                                                                                      and ((#s86 <= 1.0)
                                                                                                                                                                                                        and ((#s53 <= 0.5)
                                                                                                                                                                                                          and ((#s159 <= 0.5)
                                                                                                                                                                                                            and ((#s82 <= 1.0)
                                                                                                                                                                                                              and ((#s741 <= 0.5)
                                                                                                                                                                                                                and ((#s742 <= 1.0)
                                                                                                                                                                                                                  and ((#s42 <= 1.0)
                                                                                                                                                                                                                    and ((filesize <= 174332.0)
                                                                                                                                                                                                                      and ((filesize <= 173138.0)
                                                                                                                                                                                                                        and ((filesize <= 171387.0)
                                                                                                                                                                                                                        ) or (filesize > 173138.0)
                                                                                                                                                                                                                      ) or (filesize > 174332.0)
                                                                                                                                                                                                                      and ((filesize > 409912.0)
                                                                                                                                                                                                                        and ((filesize <= 415350.0)
                                                                                                                                                                                                                        )))))))))))))))))))))))))))))))))) or (#s80 > 0.5)
                                                                                                                                                      and ((#s36 <= 1.5)
                                                                                                                                                        and ((#s388 <= 1.0)
                                                                                                                                                          and ((filesize <= 294886.0)
                                                                                                                                                            and ((#s53 <= 1.0)
                                                                                                                                                              and ((filesize > 290858.0)
                                                                                                                                                              ))))))))))))) or (filesize > 457316.0)
                                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                                        and ((#s354 <= 0.5)
                                                                                                                                          and ((#s82 <= 0.5)
                                                                                                                                            and ((#s182 <= 0.5)
                                                                                                                                              and ((#s87 <= 0.5)
                                                                                                                                                and ((#s194 <= 0.5)
                                                                                                                                                  and ((#s179 <= 0.5)
                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                      and ((#s189 <= 1.0)
                                                                                                                                                        and ((#s812 <= 1.0)
                                                                                                                                                          and ((#s813 <= 1.0)
                                                                                                                                                            and ((#s97 <= 0.5)
                                                                                                                                                              and ((#s416 <= 0.5)
                                                                                                                                                                and ((#s150 <= 0.5)
                                                                                                                                                                  and ((#s81 <= 3.5)
                                                                                                                                                                    and ((#s818 <= 0.5)
                                                                                                                                                                      and ((#s390 <= 0.5)
                                                                                                                                                                        and ((#s76 <= 1.0)
                                                                                                                                                                          and ((#s821 <= 0.5)
                                                                                                                                                                            and ((#s47 <= 1.0)
                                                                                                                                                                              and ((#s188 <= 0.5)
                                                                                                                                                                                and ((filesize <= 468420.0)
                                                                                                                                                                                  or (filesize > 468420.0)
                                                                                                                                                                                  and ((#s159 <= 0.5)
                                                                                                                                                                                    and ((#s729 <= 0.5)
                                                                                                                                                                                      and ((#s828 <= 0.5)
                                                                                                                                                                                        and ((#s177 <= 91.0)
                                                                                                                                                                                          and ((filesize <= 620416.0)
                                                                                                                                                                                            and ((#s43 <= 1.0)
                                                                                                                                                                                              and ((#s53 <= 0.5)
                                                                                                                                                                                                and ((filesize > 606116.0)
                                                                                                                                                                                                ))) or (filesize > 620416.0)
                                                                                                                                                                                            and ((#s742 <= 1.0)
                                                                                                                                                                                              and ((#s43 <= 1.0)
                                                                                                                                                                                                and ((#s90 <= 1.0)
                                                                                                                                                                                                  and ((#s841 <= 0.5)
                                                                                                                                                                                                    and ((#s23 <= 0.5)
                                                                                                                                                                                                      and ((#s53 <= 0.5)
                                                                                                                                                                                                        and ((#s184 <= 4.0)
                                                                                                                                                                                                          and ((filesize > 1866227.5)
                                                                                                                                                                                                            and ((filesize <= 1923125.5)
                                                                                                                                                                                                            )))))))))))))))) or (#s47 > 1.0)
                                                                                                                                                                              and ((#s353 <= 1.0)
                                                                                                                                                                                and ((#s154 <= 1.0)
                                                                                                                                                                                  and ((#s864 <= 0.5)
                                                                                                                                                                                    and ((#s52 <= 0.5)
                                                                                                                                                                                      and ((filesize <= 624612.0)
                                                                                                                                                                                        and ((filesize > 586212.0)
                                                                                                                                                                                        )))))))))))) or (#s150 > 0.5)
                                                                                                                                                                ))))) or (#s189 > 1.0)
                                                                                                                                                        and ((#s72 <= 0.5)
                                                                                                                                                        )) or (#s80 > 0.5)
                                                                                                                                                      and ((#s162 <= 0.5)
                                                                                                                                                        and ((#s729 <= 0.5)
                                                                                                                                                          and ((#s890 <= 0.5)
                                                                                                                                                            and ((#s891 <= 0.5)
                                                                                                                                                              and ((#s169 <= 0.5)
                                                                                                                                                                and ((#s43 <= 1.0)
                                                                                                                                                                  and ((#s53 <= 0.5)
                                                                                                                                                                    and ((#s895 <= 0.5)
                                                                                                                                                                      and ((#s896 <= 0.5)
                                                                                                                                                                        and ((#s52 > 1.5)
                                                                                                                                                                          and ((filesize <= 854869.5)
                                                                                                                                                                          ))))))))))))))))))))))) or (#s657 > 1.0)
                                                                                                                            ))) or (#s74 > 0.5)
                                                                                                                        and ((#s21 <= 0.5)
                                                                                                                          and ((#s157 <= 0.5)
                                                                                                                            and ((#s926 <= 0.5)
                                                                                                                              and ((#s927 <= 0.5)
                                                                                                                                and ((#s175 <= 0.5)
                                                                                                                                  and ((#s929 <= 0.5)
                                                                                                                                    and ((#s90 > 1.5)
                                                                                                                                      and ((#s184 <= 1.0)
                                                                                                                                        and ((#s933 <= 1.0)
                                                                                                                                          and ((#s934 <= 2.0)
                                                                                                                                            and ((#s524 > 1.5)
                                                                                                                                            )))))))))))) or (#s653 > 0.5)
                                                                                                                      and ((#s947 <= 0.5)
                                                                                                                        and ((#s435 <= 0.5)
                                                                                                                        )))) or (#s651 > 2.0)
                                                                                                                ) or (#s650 > 0.5)
                                                                                                                and ((#s934 <= 1.0)
                                                                                                                )) or (#s649 > 0.5)
                                                                                                              and ((#s74 <= 3.0)
                                                                                                                and ((#s285 <= 0.5)
                                                                                                                ))) or (#s648 > 0.5)
                                                                                                            and ((#s933 <= 0.5)
                                                                                                            )) or (#s431 > 0.5)
                                                                                                          and ((#s285 <= 0.5)
                                                                                                            and ((#s742 <= 1.0)
                                                                                                              and ((#s96 <= 0.5)
                                                                                                                and ((#s733 <= 0.5)
                                                                                                                  and ((#s293 <= 0.5)
                                                                                                                    and ((#s734 <= 0.5)
                                                                                                                      and ((#s53 <= 1.0)
                                                                                                                        and ((#s972 <= 1.0)
                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                            and ((#s357 <= 0.5)
                                                                                                                              and ((#s435 <= 0.5)
                                                                                                                                and ((#s87 <= 0.5)
                                                                                                                                  and ((#s154 <= 0.5)
                                                                                                                                    and ((#s978 <= 1.0)
                                                                                                                                      and ((#s979 <= 1.5)
                                                                                                                                        and ((#s175 <= 0.5)
                                                                                                                                          and ((#s981 <= 1.0)
                                                                                                                                            and ((#s159 <= 0.5)
                                                                                                                                              and ((#s82 <= 0.5)
                                                                                                                                                and ((#s305 <= 0.5)
                                                                                                                                                  and ((#s812 <= 0.5)
                                                                                                                                                    and ((#s741 <= 1.0)
                                                                                                                                                      and ((#s987 <= 0.5)
                                                                                                                                                        and ((#s57 <= 3.0)
                                                                                                                                                          and ((#s989 <= 1.0)
                                                                                                                                                            and ((#s51 <= 0.5)
                                                                                                                                                              and ((#s818 <= 0.5)
                                                                                                                                                                and ((#s43 <= 0.5)
                                                                                                                                                                  and ((#s42 <= 0.5)
                                                                                                                                                                    and ((#s890 <= 0.5)
                                                                                                                                                                      and ((#s182 <= 0.5)
                                                                                                                                                                        and ((#s47 <= 1.0)
                                                                                                                                                                          and ((filesize > 318320.0)
                                                                                                                                                                            and ((#s999 <= 0.5)
                                                                                                                                                                              and ((#s179 <= 0.5)
                                                                                                                                                                                and ((#s388 <= 1.0)
                                                                                                                                                                                  and ((#s431 <= 1.5)
                                                                                                                                                                                    and ((#s57 > 1.5)
                                                                                                                                                                                      and ((filesize <= 507304.0)
                                                                                                                                                                                        and ((#s1006 <= 1.0)
                                                                                                                                                                                          and ((#s1007 <= 0.5)
                                                                                                                                                                                            and ((#s173 <= 0.5)
                                                                                                                                                                                              and ((#s1009 <= 0.5)
                                                                                                                                                                                                and ((#s52 <= 0.5)
                                                                                                                                                                                                  and ((#s465 <= 0.5)
                                                                                                                                                                                                    and ((filesize > 490808.0)
                                                                                                                                                                                                    ))))))))))) or (#s179 > 0.5)
                                                                                                                                                                                and ((filesize <= 351736.0)
                                                                                                                                                                                ))))))))))))))))))))))))))))))))) or (#s96 > 0.5)
                                                                                                                and ((#s716 <= 1.0)
                                                                                                                  and ((#s63 > 0.5)
                                                                                                                    and ((#s185 <= 0.5)
                                                                                                                      and ((#s187 > 0.5)
                                                                                                                      )))))) or (#s285 > 0.5)
                                                                                                            and ((#s390 <= 1.5)
                                                                                                              and ((#s929 <= 0.5)
                                                                                                                and ((#s435 <= 0.5)
                                                                                                                  and ((#s648 > 0.5)
                                                                                                                  ))) or (#s390 > 1.5)
                                                                                                              and ((#s56 <= 0.5)
                                                                                                                and ((#s63 <= 0.5)
                                                                                                                  and ((#s431 <= 1.5)
                                                                                                                    and ((#s1078 > 0.5)
                                                                                                                      and ((#s1080 <= 0.5)
                                                                                                                      )))))))))) or (#s644 > 1.5)
                                                                                                    and ((#s1088 <= 1.0)
                                                                                                      and ((#s285 <= 1.0)
                                                                                                        and ((#s1090 <= 1.0)
                                                                                                          or (#s1090 > 1.0)
                                                                                                          and ((#s1092 > 3.0)
                                                                                                          ))))) or (#s643 > 0.5)
                                                                                                  and ((#s1090 > 0.5)
                                                                                                    and ((#s586 > 0.5)
                                                                                                      and ((#s31 <= 1.5)
                                                                                                        and ((#s27 <= 3.0)
                                                                                                        ))))) or (#s642 > 0.5)
                                                                                              ) or (#s641 > 0.5)
                                                                                            ) or (#s640 > 0.5)
                                                                                          ) or (#s639 > 2.5)
                                                                                          and ((#s85 > 0.5)
                                                                                            and ((#s40 > 0.5)
                                                                                            ))) or (#s638 > 1.5)
                                                                                        and ((#s50 <= 0.5)
                                                                                          and ((#s84 <= 1.0)
                                                                                            and ((#s1116 <= 2.0)
                                                                                              and ((#s96 <= 0.5)
                                                                                                and ((#s440 <= 1.0)
                                                                                                  and ((#s80 <= 1.0)
                                                                                                  ))))))) or (#s513 > 4.0)
                                                                                    )) or (#s635 > 0.5)
                                                                                ) or (#s634 > 0.5)
                                                                              ) or (#s633 > 0.5)
                                                                            ) or (#s632 > 0.5)
                                                                          ) or (#s631 > 0.5)
                                                                          and ((#s890 <= 34.5)
                                                                            and ((#s631 <= 1.5)
                                                                              and ((#s87 <= 2.0)
                                                                                and ((#s154 > 1.0)
                                                                                ))) or (#s890 > 34.5)
                                                                          )) or (#s630 > 1.0)
                                                                      ) or (#s629 > 0.5)
                                                                    ) or (#s295 > 1.0)
                                                                  ) or (#s627 > 0.5)
                                                                ) or (#s626 > 0.5)
                                                              ) or (#s625 > 0.5)
                                                            ) or (#s624 > 0.5)
                                                          ) or (#s623 > 0.5)
                                                        ) or (#s622 > 0.5)
                                                      ) or (#s621 > 2.0)
                                                    ) or (#s620 > 1.0)
                                                  )) or (#s21 > 1.5)
                                                and ((#s57 <= 0.5)
                                                  and ((#s388 <= 0.5)
                                                    and ((#s63 <= 0.5)
                                                      and ((#s1156 <= 0.5)
                                                        and ((#s1157 <= 1.5)
                                                          and ((#s175 > 1.5)
                                                            and ((#s407 <= 1.0)
                                                              and ((#s285 <= 0.5)
                                                              ))))))) or (#s57 > 0.5)
                                                  and ((#s1169 <= 0.5)
                                                    and ((#s1080 <= 0.5)
                                                      and ((#s1171 > 1.0)
                                                        and ((#s152 <= 1.0)
                                                        ))) or (#s1169 > 0.5)
                                                  ))) or (#s20 > 0.5)
                                            ) or (#s19 > 0.5)
                                            and ((#s326 <= 0.5)
                                              and ((#s733 <= 1.5)
                                                and ((#s291 <= 0.5)
                                                  and ((#s72 <= 0.5)
                                                    and ((#s1183 <= 0.5)
                                                      and ((#s75 <= 0.5)
                                                        and ((filesize > 647376.0)
                                                          and ((#s354 > 1.5)
                                                            and ((#s179 > 0.5)
                                                              and ((#s293 <= 0.5)
                                                              ))))) or (#s1183 > 0.5)
                                                      and ((#s926 <= 1.0)
                                                      )))) or (#s733 > 1.5)
                                                and ((#s1200 > 0.5)
                                                )) or (#s326 > 0.5)
                                            )) or (#s18 > 0.5)
                                        ) or (#s17 > 0.5)
                                      ) or (#s16 > 0.5)
                                      and ((filesize <= 1348088.0)
                                        and ((#s1207 <= 0.5)
                                        ) or (filesize > 1348088.0)
                                      )) or (#s15 > 0.5)
                                    and ((#s1211 <= 0.5)
                                      and ((#s43 <= 1.0)
                                      ))) or (#s14 > 1.5)
                                  and ((#s1216 <= 1.0)
                                    and ((#s353 > 1.0)
                                      and ((#s51 <= 2.5)
                                        and ((filesize <= 18120.0)
                                          and ((filesize <= 16072.0)
                                            and ((filesize > 10528.0)
                                              and ((filesize <= 12038.0)
                                              ))) or (filesize > 18120.0)
                                          and ((#s1230 <= 0.5)
                                            and ((filesize > 53008.0)
                                            ) or (#s1230 > 0.5)
                                          )))))) or (#s13 > 0.5)
                              ) or (#s12 > 0.5)
                            ) or (#s11 > 0.5)
                            and ((#s357 <= 1.0)
                              and ((filesize > 676020.0)
                              ))) or (#s10 > 0.5)
                          and ((#s1244 <= 0.5)
                            and ((#s1245 <= 1.0)
                              and ((#s165 <= 1.5)
                                and ((filesize <= 397272.0)
                                  and ((#s1088 <= 0.5)
                                    and ((#s43 > 1.0)
                                    ) or (#s1088 > 0.5)
                                    and ((#s74 > 0.5)
                                    )))) or (#s1245 > 1.0)
                            ) or (#s1244 > 0.5)
                            and ((#s285 > 0.5)
                              and ((#s179 > 0.5)
                                and ((#s1262 > 0.5)
                                ))))) or (#s9 > 0.5)
                      ) or (#s8 > 0.5)
                      and ((#s1266 <= 1.0)
                        and ((#s1080 <= 0.5)
                          and ((#s63 <= 2.5)
                            and ((#s1269 <= 0.5)
                              and ((#s1270 <= 0.5)
                                and ((#s97 <= 1.0)
                                  and ((#s90 <= 1.5)
                                    and ((#s1273 > 0.5)
                                      and ((#s609 > 0.5)
                                      ))) or (#s97 > 1.0)
                                  and ((#s187 <= 0.5)
                                  )) or (#s1270 > 0.5)
                              ) or (#s1269 > 0.5)
                              and ((#s1283 <= 2.0)
                                and ((#s609 <= 0.5)
                                  and ((#s1285 <= 0.5)
                                    and ((#s85 <= 1.5)
                                      and ((#s1116 <= 0.5)
                                        and ((#s1244 <= 0.5)
                                          and ((#s1289 > 0.5)
                                            and ((#s933 <= 0.5)
                                            )) or (#s1244 > 0.5)
                                        )) or (#s85 > 1.5)
                                    ) or (#s1285 > 0.5)
                                  ) or (#s609 > 0.5)
                                ) or (#s1283 > 2.0)
                              )) or (#s63 > 2.5)
                            and ((#s1300 <= 1.0)
                              and ((#s96 > 1.5)
                                and ((#s591 > 0.5)
                                )) or (#s1300 > 1.0)
                            )) or (#s1080 > 0.5)
                          and ((#s1307 <= 1.5)
                            and ((#s1308 <= 1.5)
                              and ((#s1309 <= 1.0)
                                and ((#s357 <= 0.5)
                                  or (#s357 > 0.5)
                                  and ((#s75 <= 0.5)
                                    and ((#s390 > 3.5)
                                      and ((#s666 > 2.0)
                                      )) or (#s75 > 0.5)
                                    and ((#s85 <= 1.5)
                                      and ((#s643 <= 1.5)
                                        and ((#s21 <= 1.0)
                                          and ((#s1321 > 0.5)
                                            and ((#s354 > 0.5)
                                            )) or (#s21 > 1.0)
                                          and ((#s164 <= 1.0)
                                            or (#s164 > 1.0)
                                            and ((#s828 <= 1.0)
                                            ))))))) or (#s1309 > 1.0)
                              ) or (#s1308 > 1.5)
                              and ((#s1334 <= 0.5)
                                and ((#s1335 > 0.5)
                                ))) or (#s1307 > 1.5)
                            and ((#s1339 <= 0.5)
                              and ((#s513 <= 1.5)
                              )))) or (#s1266 > 1.0)
                      )) or (#s7 > 1.0)
                    and ((#s179 <= 2.5)
                      and ((#s159 <= 0.5)
                        and ((#s1347 <= 0.5)
                          and ((#s1348 <= 1.0)
                            and ((#s1349 > 0.5)
                            )) or (#s1347 > 0.5)
                        )) or (#s179 > 2.5)
                    )) or (#s6 > 1.0)
                  and ((#s609 <= 0.5)
                    and ((#s675 <= 1.0)
                      and ((#s1358 <= 0.5)
                        and ((#s1359 <= 3.0)
                          and ((#s86 <= 1.0)
                            and ((#s1361 <= 1.0)
                              and ((#s431 <= 0.5)
                                and ((#s1363 <= 1.5)
                                  and ((#s84 <= 1.0)
                                    and ((#s1365 <= 13.5)
                                      and ((#s286 > 1.0)
                                        and ((#s173 <= 0.5)
                                        )))) or (#s1363 > 1.5)
                                )) or (#s1361 > 1.0)
                            )) or (#s1359 > 3.0)
                        ) or (#s1358 > 0.5)
                      ) or (#s675 > 1.0)
                      and ((#s733 <= 0.5)
                      )) or (#s609 > 0.5)
                    and ((#s194 > 2.5)
                      and ((#s285 <= 0.5)
                      )))) or (#s5 > 0.5)
              ) or (#s4 > 0.5)
            ) or (#s3 > 0.5)
          ) or (#s2 > 0.5)
          and ((#s1390 <= 1.0)
            and ((#s1211 <= 0.5)
              and ((#s1392 <= 0.5)
                and ((#s1393 <= 2.5)
                  and ((#s514 <= 1.5)
                    and ((#s1395 <= 1.0)
                      and ((#s64 <= 2.5)
                        and ((#s1397 <= 0.5)
                          and ((#s61 <= 0.5)
                            and ((#s164 <= 1.0)
                              and ((#s1400 <= 0.5)
                                and ((#s1401 <= 1.0)
                                  and ((#s639 <= 1.5)
                                    and ((#s648 <= 0.5)
                                      and ((#s147 <= 3.0)
                                        and ((filesize <= 233560.0)
                                          and ((#s1406 <= 0.5)
                                            and ((#s179 <= 0.5)
                                              and ((#s67 <= 0.5)
                                                and ((#s999 <= 0.5)
                                                  and ((#s73 > 1.0)
                                                    and ((#s1078 <= 0.5)
                                                      and ((#s1413 <= 0.5)
                                                        and ((#s64 > 1.0)
                                                          and ((#s1300 <= 1.0)
                                                          )) or (#s1413 > 0.5)
                                                      )))) or (#s67 > 0.5)
                                                and ((#s1422 <= 0.5)
                                                  and ((#s293 <= 0.5)
                                                    and ((#s1424 <= 0.5)
                                                      or (#s1424 > 0.5)
                                                      and ((#s23 <= 0.5)
                                                        and ((#s1078 > 0.5)
                                                        ) or (#s23 > 0.5)
                                                      ))) or (#s1422 > 0.5)
                                                ))))) or (#s147 > 3.0)
                                      ) or (#s648 > 0.5)
                                      and ((#s1437 <= 0.5)
                                        and ((#s933 <= 1.0)
                                        )))) or (#s1401 > 1.0)
                                ) or (#s1400 > 0.5)
                              ) or (#s164 > 1.0)
                              and ((#s1335 <= 0.5)
                                and ((#s73 > 2.5)
                                  and ((#s1448 > 0.5)
                                    and ((#s293 <= 0.5)
                                    ))) or (#s1335 > 0.5)
                                and ((#s194 > 0.5)
                                ))) or (#s61 > 0.5)
                            and ((#s1456 <= 0.5)
                              and ((#s1457 <= 0.5)
                                and ((#s157 <= 2.5)
                                  and ((#s934 <= 1.0)
                                    and ((#s352 <= 1.0)
                                      and ((#s643 <= 3.0)
                                        and ((#s1424 <= 0.5)
                                          and ((#s75 <= 1.0)
                                            and ((#s828 <= 1.0)
                                            ))) or (#s643 > 3.0)
                                      ))) or (#s157 > 2.5)
                                  and ((#s716 > 1.0)
                                    and ((#s1474 > 0.5)
                                    ))) or (#s1457 > 0.5)
                              ) or (#s1456 > 0.5)
                              and ((#s50 <= 0.5)
                                or (#s50 > 0.5)
                                and ((#s585 <= 8.0)
                                  and ((filesize <= 5022495.5)
                                    or (filesize > 5022495.5)
                                    and ((#s1483 <= 1.0)
                                      and ((#s514 > 0.5)
                                        and ((filesize <= 10092017.0)
                                        )))))))) or (#s1397 > 0.5)
                        ) or (#s64 > 2.5)
                        and ((#s585 <= 3.5)
                          and ((#s591 <= 0.5)
                            and ((#s1494 <= 0.5)
                              and ((#s171 <= 0.5)
                                and ((#s1496 <= 0.5)
                                  or (#s1496 > 0.5)
                                  and ((#s188 <= 0.5)
                                    and ((#s524 > 0.5)
                                    ) or (#s188 > 0.5)
                                  )) or (#s171 > 0.5)
                              )) or (#s591 > 0.5)
                            and ((#s57 <= 1.5)
                              and ((#s152 <= 1.0)
                              ) or (#s57 > 1.5)
                              and ((#s1509 <= 1.0)
                                and ((#s291 <= 1.0)
                                  and ((#s644 <= 0.5)
                                    or (#s644 > 0.5)
                                    and ((#s1300 <= 1.0)
                                      and ((#s1514 > 0.5)
                                      ) or (#s1300 > 1.0)
                                    )))))) or (#s585 > 3.5)
                          and ((#s352 <= 1.0)
                            and ((#s1456 <= 1.5)
                              and ((#s1522 > 2.0)
                              ))))) or (#s1395 > 1.0)
                      and ((#s1200 > 1.0)
                      )) or (#s514 > 1.5)
                    and ((#s1530 <= 1.0)
                      and ((#s1400 <= 1.5)
                        and ((#s41 <= 0.5)
                          and ((#s1533 > 2.5)
                            and ((#s1535 > 2.0)
                            )) or (#s41 > 0.5)
                          and ((filesize <= 16100192.0)
                            and ((#s1539 <= 1.0)
                              and ((#s388 <= 1.0)
                                and ((#s1541 <= 2.0)
                                  and ((#s416 <= 1.0)
                                    and ((#s514 <= 2.5)
                                      and ((#s1544 > 0.5)
                                      ) or (#s514 > 2.5)
                                      and ((#s1547 <= 2.5)
                                        or (#s1547 > 2.5)
                                        and ((#s194 <= 2.5)
                                          and ((#s70 <= 0.5)
                                            or (#s70 > 0.5)
                                            and ((filesize > 7098608.0)
                                            )))))) or (#s1541 > 2.0)
                                ) or (#s388 > 1.0)
                                and ((filesize > 11960896.0)
                                  and ((#s16 > 2.5)
                                  )))) or (filesize > 16100192.0)
                            and ((#s729 <= 3.0)
                              and ((#s987 <= 1.5)
                                and ((#s1566 > 0.5)
                                ) or (#s987 > 1.5)
                              ) or (#s729 > 3.0)
                              and ((#s1007 <= 1.0)
                                and ((#s1571 <= 1.0)
                                  and ((#s630 <= 1.0)
                                    and ((filesize <= 17175080.0)
                                    )) or (#s1571 > 1.0)
                                  and ((#s81 <= 32.0)
                                    and ((filesize <= 24226160.0)
                                    ) or (#s81 > 32.0)
                                    and ((filesize > 25131176.0)
                                      and ((filesize <= 25131192.0)
                                      )))) or (#s1007 > 1.0)
                                and ((#s1586 <= 0.5)
                                  or (#s1586 > 0.5)
                                  and ((#s1588 <= 0.5)
                                  ))))))) or (#s1530 > 1.0)
                      and ((#s7 > 1.0)
                      ))) or (#s1393 > 2.5)
                ) or (#s1392 > 0.5)
              ) or (#s1211 > 0.5)
              and ((#s1597 <= 0.5)
                and ((#s1598 <= 0.5)
                  and ((#s353 <= 1.0)
                  )) or (#s1597 > 0.5)
                and ((#s81 <= 18.5)
                  and ((#s1604 > 0.5)
                    and ((#s73 > 2.5)
                      and ((#s1514 <= 0.5)
                      )))))) or (#s1390 > 1.0)
            and ((#s47 <= 1.0)
              and ((#s649 <= 0.5)
                and ((#s1614 <= 0.5)
                  and ((#s733 <= 0.5)
                    and ((#s1171 > 2.5)
                    )) or (#s1614 > 0.5)
                ) or (#s649 > 0.5)
                and ((#s1400 > 0.5)
                )) or (#s47 > 1.0)
              and ((#s585 <= 30.0)
                and ((#s1625 > 1.0)
                ))))) or (#s1 > 0.5)
        and ((#s729 <= 1.5)
          and ((#s74 <= 0.5)
            and ((#s1631 <= 0.5)
              and ((#s1632 <= 1.0)
                and ((#s1633 <= 4.5)
                  and ((#s1634 <= 0.5)
                    and ((#s47 <= 1.0)
                      and ((#s1636 > 0.5)
                      ))) or (#s1633 > 4.5)
                  and ((#s1641 <= 4.0)
                    and ((#s173 > 0.5)
                    )))) or (#s1631 > 0.5)
            ) or (#s74 > 0.5)
            and ((#s63 <= 0.5)
              and ((#s987 > 0.5)
                and ((#s1651 > 0.5)
                )) or (#s63 > 0.5)
              and ((#s649 > 1.0)
              ))) or (#s729 > 1.5)
          and ((#s390 <= 0.5)
            and ((#s1658 <= 0.5)
              and ((#s286 <= 1.0)
                and ((#s6 <= 16.0)
                  and ((#s1661 <= 1.0)
                    and ((#s154 > 1.0)
                    ) or (#s1661 > 1.0)
                  )) or (#s286 > 1.0)
                and ((#s357 <= 0.5)
                  and ((#s1668 <= 0.5)
                    and ((#s1669 <= 2.5)
                      and ((#s431 <= 0.5)
                        and ((#s1633 <= 6.0)
                          and ((#s1672 <= 10.0)
                          ))) or (#s1669 > 2.5)
                    ) or (#s1668 > 0.5)
                  ) or (#s357 > 0.5)
                  and ((#s7 <= 1.0)
                  ))) or (#s1658 > 0.5)
            ) or (#s390 > 0.5)
            and ((#s649 > 0.5)
              and ((#s43 > 1.0)
              ))))) or (#s0 > 0.5)
      and ((#s1688 <= 2.5)
        and ((#s1689 <= 0.5)
          and ((#s1690 <= 1.5)
            and ((#s934 <= 1.0)
              and ((#s75 > 2.5)
                and ((#s149 > 1.0)
                  and ((#s96 <= 0.5)
                    and ((#s285 > 0.5)
                      and ((#s305 > 0.5)
                      ))))) or (#s934 > 1.0)
              and ((#s933 <= 1.0)
              )) or (#s1690 > 1.5)
            and ((#s1706 <= 2.0)
              and ((#s291 <= 1.0)
                and ((#s200 <= 1.0)
                  and ((#s151 <= 1.0)
                    and ((#s45 <= 0.5)
                      and ((#s1711 <= 1.0)
                        and ((#s1712 <= 0.5)
                          and ((#s1474 <= 0.5)
                            and ((#s1714 <= 1.0)
                              and ((#s1715 <= 1.5)
                                and ((#s179 <= 0.5)
                                  and ((#s88 <= 1.5)
                                    and ((#s415 <= 1.0)
                                      and ((#s1719 <= 0.5)
                                        and ((#s1308 <= 0.5)
                                          and ((#s1721 <= 1.0)
                                            and ((#s524 <= 0.5)
                                              and ((#s1723 <= 1.0)
                                                and ((#s1393 > 0.5)
                                                ) or (#s1723 > 1.0)
                                              )) or (#s1721 > 1.0)
                                            and ((#s90 <= 1.0)
                                              and ((#s1730 > 0.5)
                                              ) or (#s90 > 1.0)
                                              and ((#s96 <= 0.5)
                                                and ((#s1734 <= 0.5)
                                                  and ((#s1078 <= 0.5)
                                                    and ((#s431 <= 0.5)
                                                      or (#s431 > 0.5)
                                                      and ((#s1738 <= 0.5)
                                                        and ((#s633 <= 1.5)
                                                          and ((#s63 > 2.5)
                                                          ) or (#s633 > 1.5)
                                                        ))) or (#s1078 > 0.5)
                                                  )) or (#s96 > 0.5)
                                                and ((#s390 > 1.0)
                                                )))))) or (#s415 > 1.0)
                                      and ((#s186 > 1.0)
                                      ))) or (#s179 > 0.5)
                                  and ((#s74 > 2.0)
                                    and ((#s173 <= 0.5)
                                    ))))) or (#s1474 > 0.5)
                            and ((#s709 <= 2.0)
                              and ((#s1764 <= 0.5)
                                and ((#s1719 <= 0.5)
                                  and ((#s194 > 2.0)
                                  )) or (#s1764 > 0.5)
                              ) or (#s709 > 2.0)
                              and ((#s896 <= 0.5)
                              )))) or (#s1711 > 1.0)
                        and ((#s709 <= 1.0)
                          and ((#s194 > 2.0)
                          ))))) or (#s200 > 1.0)
                  and ((#s151 <= 0.5)
                    and ((#s21 <= 1.0)
                      and ((#s149 <= 5.0)
                        and ((#s1785 > 4.5)
                        ) or (#s149 > 5.0)
                      ) or (#s21 > 1.0)
                      and ((#s1496 <= 0.5)
                        and ((#s656 <= 0.5)
                          and ((#s1791 > 0.5)
                          ) or (#s656 > 0.5)
                        ))))) or (#s291 > 1.0)
                and ((#s187 <= 0.5)
                  and ((#s194 > 0.5)
                    and ((#s305 <= 0.5)
                      and ((#s422 <= 1.0)
                        and ((#s591 <= 0.5)
                          and ((#s1803 <= 1.0)
                            and ((#s434 > 1.0)
                            )))))) or (#s187 > 0.5)
                  and ((#s1335 <= 0.5)
                    and ((#s50 <= 0.5)
                      and ((#s178 <= 0.5)
                        and ((#s1157 <= 0.5)
                          and ((#s1078 > 0.5)
                          ) or (#s1157 > 0.5)
                        ) or (#s178 > 0.5)
                        and ((#s435 > 0.5)
                        )))))))) or (#s1689 > 0.5)
          and ((#s73 <= 1.5)
            and ((#s586 <= 2.5)
              and ((#s1262 > 1.0)
              ) or (#s586 > 2.5)
              and ((#s1830 <= 0.5)
                and ((#s56 <= 0.5)
                  and ((#s67 <= 0.5)
                    and ((#s96 <= 0.5)
                      and ((#s175 > 1.0)
                      ))) or (#s56 > 0.5)
                  and ((#s648 <= 0.5)
                    and ((#s1604 <= 0.5)
                      and ((#s416 <= 1.0)
                        and ((#s171 <= 1.5)
                          and ((#s1791 > 0.5)
                            and ((#s591 <= 0.5)
                              and ((#s164 > 1.5)
                                and ((#s1848 <= 3.0)
                                  and ((#s61 <= 0.5)
                                    and ((#s66 <= 0.5)
                                      and ((#s2 <= 0.5)
                                      )) or (#s61 > 0.5)
                                  ) or (#s1848 > 3.0)
                                )))) or (#s171 > 1.5)
                          and ((#s293 <= 1.0)
                          ))) or (#s1604 > 0.5)
                    ) or (#s648 > 0.5)
                    and ((#s639 <= 2.5)
                    ))) or (#s1830 > 0.5)
                and ((#s1866 <= 3.5)
                ))) or (#s73 > 1.5)
            and ((#s1791 <= 0.5)
              and ((#s1870 <= 1.5)
                and ((#s929 <= 0.5)
                  and ((#s1872 <= 2.0)
                    and ((#s1873 <= 1.0)
                      and ((#s650 <= 2.0)
                        and ((filesize <= 131176.0)
                          and ((#s586 <= 2.5)
                            and ((#s1715 > 1.0)
                            ) or (#s586 > 2.5)
                            and ((#s1321 > 0.5)
                              and ((#s1882 <= 1.5)
                                and ((#s162 <= 0.5)
                                  and ((#s591 <= 0.5)
                                    and ((#s151 <= 2.0)
                                      and ((#s305 > 0.5)
                                      )) or (#s591 > 0.5)
                                    and ((#s390 > 1.0)
                                    ))))))) or (#s650 > 2.0)
                      ) or (#s1873 > 1.0)
                    ) or (#s1872 > 2.0)
                  )) or (#s1870 > 1.5)
                and ((#s1900 > 1.5)
                  and ((#s57 > 1.0)
                  ))) or (#s1791 > 0.5)
              and ((#s21 <= 1.0)
                and ((#s1906 <= 0.5)
                  and ((#s57 <= 1.5)
                    and ((#s1908 <= 1.0)
                      and ((#s677 > 0.5)
                        and ((#s1848 > 4.5)
                          and ((#s513 > 0.5)
                          )))) or (#s57 > 1.5)
                    and ((#s188 <= 0.5)
                      and ((#s1400 <= 2.5)
                      ))) or (#s1906 > 0.5)
                  and ((#s649 <= 0.5)
                  )) or (#s21 > 1.0)
              )))) or (#s1688 > 2.5)
        and ((#s97 > 1.5)
          and ((#s926 <= 1.0)
            and ((#s1080 <= 1.0)
              and ((#s388 <= 2.0)
                and ((#s1931 <= 5.0)
                  and ((#s149 <= 1.0)
                    and ((#s175 <= 1.0)
                      and ((#s31 <= 3.0)
                        and ((#s1935 > 2.0)
                          and ((filesize <= 232856.0)
                          )))) or (#s149 > 1.0)
                    and ((#s1942 <= 1.5)
                      and ((#s75 <= 3.0)
                      ) or (#s1942 > 1.5)
                    )))))))))
}