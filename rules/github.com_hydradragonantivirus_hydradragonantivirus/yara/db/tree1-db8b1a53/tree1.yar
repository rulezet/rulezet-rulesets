rule tree1 {
  strings:
    $s0    = "kSecAttrProtocolFTP" fullword
    $s1    = "forKeyedSubscriptP19NSMutableDictionaryP13objc" fullword
    $s2    = "configureFromArgEPKc" fullword
    $s3    = "ZBULocalizationContext" fullword
    $s4    = "continueUserActivity" fullword
    $s5    = "SecTransformExecute" fullword
    $s6    = "ZTVN5boost4asio5error6detail12ssl" fullword
    $s7    = "IORegistryEntryCreateCFProperty" fullword
    $s8    = "ZBLocalizationContext" fullword
    $s9    = "EqualizationPhase1" fullword
    $s10   = "setSearchProvider" fullword
    $s11   = "113EmptyIterator4SeekERKNS" fullword
    $s12   = "113EmptyIteratorE" fullword
    $s13   = "setStandardOutput" fullword
    $s14   = "getblocktemplate" fullword
    $s15   = "uriuwfgjZasjXjjgZg" fullword
    $s16   = "dictionaryWithJSONString" fullword
    $s17   = "DraggingViewNotificationIcon" fullword
    $s18   = "UHAWAVAUATSPIIIu0Ht" fullword
    $s19   = "ZN9QListData7disposeEPNS" fullword
    $s20   = "140213191008Z0A1" fullword
    $s21   = "11checkObjectERKNSt3" fullword
    $s22   = "KGCustButtonView" fullword
    $s23   = "linenoiseEditMoveHome" fullword
    $s24   = "20191105000000Z0" fullword
    $s25   = "UHAWAVAUATSHXIcHcH" fullword
    $s26   = "140129192647Z0A1" fullword
    $s27   = "systemScanPartialFixDone" fullword
    $s28   = "lastCrcListValuesCount" fullword
    $s29   = "licenseActivated" fullword
    $s30   = "sizeOfItemAtPath" fullword
    $s31   = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s32   = "ZBNetworkReachability" fullword
    $s33   = "lockScreenAuthenticationDidFailWithAttempt" fullword
    $s34   = "HEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEgqV" fullword
    $s35   = "ZN22DbMultipleDataIterator4nextER3Dbt" fullword
    $s36   = "addCleanerRemovedSize" fullword
    $s37   = "invocationWithTarget" fullword
    $s38   = "UserNotifications" fullword
    $s39   = "CFBundleIdentifier" fullword
    $s40   = "SystemConfiguration" fullword
    $s41   = "UHAWAVAUATSHHHuE" fullword
    $s42   = "launchJavaApplication" fullword
    $s43   = "kZBVTInstallerDownloadPathKey" fullword
    $s44   = "terminationStatus" fullword
    $s45   = "hasItemWithDisplayName" fullword
    $s46   = "countByEnumeratingWithState" fullword
    $s47   = "ZTSN10CryptoNote29KVBinaryInputStreamSerializerE" fullword
    $s48   = "iPhoneSimulator10" fullword
    $s49   = "certificateauthority0" fullword
    $s50   = "ZTI15CCoinsViewCache" fullword
    $s51   = "applicationWillHide" fullword
    $s52   = "270201221215Z0y1" fullword
    $s53   = "abcdefghijklmnopqrstuvwxyz" fullword
    $s54   = "initWithCapacity" fullword
    $s55   = "SleepNotificationMBS" fullword
    $s56   = "fileExistsAtPath" fullword
    $s57   = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s58   = "localizedStringForKey" fullword
    $s59   = "FromStringAndSize" fullword
    $s60   = "3protectExecutableMemoryEPvm" fullword
    $s61   = "stringWithFormat" fullword
    $s62   = "GenerateConnectionID" fullword
    $s63   = "CFBundleExecutable" fullword
    $s64   = "IHEHEHEHEHEHEHEL" fullword
    $s65   = "350209214036Z0b1" fullword
    $s66   = "removeObjectForKey" fullword
    $s67   = "enumerationMutation" fullword
    $s68   = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s69   = "bQHbQHbQHbQHbqHbHbQHbHbQHbQHb" fullword
    $s70   = "handleHomeButtonSinglePressUp" fullword
    $s71   = "CFBundleCopyBundleURL" fullword
    $s72   = "respondsToSelector" fullword
    $s73   = "CFConstantStringClassReference" fullword
    $s74   = "ServiceManagement" fullword
    $s75   = "sqhIJsyyeFaPcYe7" fullword
    $s76   = "componentsSeparatedByString" fullword
    $s77   = "9allocatorIcEEEE" fullword
    $s78   = "DEDEDEDEDEDEDEDE9E" fullword
    $s79   = "UHAWAVAUATSPIHIIH" fullword
    $s80   = "UHAWAVAUATSPIHIH" fullword
    $s81   = "traitsIcEEE3putEc" fullword
    $s82   = "ellipticcurvelist" fullword
    $s83   = "retainAutoreleaseReturnValue" fullword
    $s84   = "HEHEHEHEHEHEHEHEHEHEHE" fullword
    $s85   = "PrivateFrameworks" fullword
    $s86   = "arrayWithObjects" fullword
    $s87   = "retainAutoreleasedReturnValue" fullword
    $s88   = "AECreateAppleEvent" fullword
    $s89   = "CFStringGetCString" fullword
    $s90   = "sharedApplication" fullword
    $s91   = "loadWeakRetained" fullword
    $s93   = "DefaultRuneLocale" fullword
    $s94   = "NSAutoreleasePool" fullword
    $s95   = "libswiftCoreFoundation" fullword
    $s96   = "getExistentialTypeMetadata" fullword
    $s97   = "ApplicationServices" fullword
    $s98   = "contentsOfDirectoryAtPath" fullword
    $s99   = "CFURLCopyFileSystemPath" fullword
    $s100  = "retainAutorelease" fullword
    $s101  = "JSValueUnprotect" fullword
    $s102  = "ZN9QListData11shared" fullword
    $s103  = "intrinsicContentSize" fullword
    $s104  = "ddddddddddddddddddddddddddddddddsd" fullword
    $s105  = "NSConcreteGlobalBlock" fullword
    $s106  = "JSObjectSetProperty" fullword
    $s107  = "debugDescription" fullword
    $s110  = "UHAWAVAUATSH8IHH" fullword
    $s111  = "copyElephantBrain" fullword
    $s112  = "ZTSN5boost9exceptionE" fullword
    $s113  = "ZN16QLoggingCategoryD1Ev" fullword
    $s114  = "CFStringCreateWithCString" fullword
    $s116  = "NSStringFromClass" fullword
    $s117  = "0123456789abcdef" fullword
    $s118  = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s119  = "dataUsingEncoding" fullword
    $s120  = "kCFAllocatorDefault" fullword
    $s121  = "UIViewController" fullword
    $s122  = "NSAddressOfSymbol" fullword
    $s123  = "autoreleasePoolPop" fullword
    $s124  = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s125  = "SecItemCopyMatching" fullword
    $s128  = "NSNotificationCenter" fullword
    $s140  = "libswiftCoreGraphics" fullword
    $s146  = "logKextUserClient" fullword
    $s151  = "libswiftDispatch" fullword
    $s152  = "ImageCaptureCore" fullword
    $s153  = "replaceCharactersInRange" fullword
    $s154  = "category23default" fullword
    $s156  = "lswiftObjectiveC" fullword
    $s166  = "DisableThreadLibraryCalls" fullword
    $s231  = "CFStringMakeConstantString" fullword
    $s234  = "KhfCECHKJKnKtDkW" fullword
    $s245  = "CFArrayGetValueAtIndex" fullword
    $s246  = "UHAWAVAUATSH8IIH" fullword
    $s247  = "redirectResponse" fullword
    $s248  = "UHAWAVAUATSH8IIHH" fullword
    $s249  = "UHAWAVAUATSH8IHuIH" fullword
    $s250  = "UHAWAVAUATSPIIHt" fullword
    $s253  = "alSourceQueueBuffers" fullword
    $s254  = "baseIN5boost9sub" fullword
    $s258  = "traitsIcEEE9showmanycEv" fullword
    $s259  = "getInstanceMethod" fullword
    $s260  = "DestroyIPN7netflix4nccp20DownloadablePlaydataES2" fullword
    $s261  = "sendCreateChannel" fullword
    $s262  = "UHAWAVAUATSH8HIH" fullword
    $s265  = "arrayOfDictionariesByMatchingRegex" fullword
    $s266  = "shouldHighlightRowAtIndexPath" fullword
    $s267  = "columnIndexForName" fullword
    $s268  = "ZTVN14RegisterResult16RegistrationDataE" fullword
    $s269  = "IOIteratorIsValid" fullword
    $s270  = "OSAtomicDecrement32" fullword
    $s272  = "mediumspringgreen" fullword
    $s273  = "nodeIPN7netflix4base6ThreadEEEC2ERKS5" fullword
    $s274  = "createFileAtPath" fullword
    $s275  = "CGContextRelease" fullword
    $s276  = "gestureRecognizer" fullword
    $s277  = "UHAWAVAUATSPIIID" fullword
    $s278  = "StringCharCodeAt" fullword
    $s279  = "resignFirstResponder" fullword
    $s280  = "UHAWAVAUATSPAAII" fullword
    $s285  = "CommitTransaction" fullword
    $s287  = "UHAWAVAUATSPAIIB" fullword
    $s288  = "getImplementation" fullword
    $s291  = "glFramebufferTextureLayer" fullword
    $s292  = "NSFetchedPropertyDescription" fullword
    $s293  = "HEHEHEHEHEHEHEHE" fullword
    $s294  = "CFURLGetFileSystemRepresentation" fullword
    $s295  = "9allocatorIcEEE6insertEmPKcm" fullword
    $s378  = "crossCertificatePair" fullword
    $s379  = "E6targetERKSt9type" fullword
    $s439  = "HMHMHMHMHMHMHMHMH" fullword
    $s442  = "N5boost9gregorian15bad" fullword
    $s445  = "traitsIcEEE5tellgEv" fullword
    $s453  = "CGRectContainsPoint" fullword
    $s455  = "autoreleaseReturnValue" fullword
    $s456  = "UIGestureRecognizer" fullword
    $s457  = "CFBundleCopyResourceURL" fullword
    $s459  = "NSMutableOrderedSet" fullword
    $s460  = "CFDictionaryCreateMutable" fullword
    $s463  = "NSFilenamesPboardType" fullword
    $s465  = "bundleIdentifier" fullword
    $s466  = "MobileCoreServices" fullword
    $s467  = "JavaApplicationStub" fullword
    $s469  = "N5boost6detail11thread" fullword
    $s525  = "arrayWithCapacity" fullword
    $s526  = "CFReadStreamCreateWithFile" fullword
    $s533  = "initWithIdentifier" fullword
    $s534  = "ZL22copySwiftV1MangledNamePKcb" fullword
    $s535  = "objectAtIndexedSubscript" fullword
    $s536  = "stringWithString" fullword
    $s537  = "objectForKeyedSubscript" fullword
    $s558  = "stringByAppendingPathComponent" fullword
    $s586  = "unretainedObject" fullword
    $s587  = "ZNK2cv3Mat5MStepixEi" fullword
    $s590  = "replaceObjectAtIndex" fullword
    $s591  = "CGContextStrokePath" fullword
    $s592  = "HK8HH8HC0HK8HA0HC8I9" fullword
    $s594  = "UHAWAVAUATSHhMMIH" fullword
    $s595  = "Internationalized" fullword
    $s612  = "140305162647Z0A1" fullword
    $s613  = "180123004003Z0A1" fullword
    $s614  = "200219223002Z0B1" fullword
    $s616  = "UHAWAVAUATSPEAIHIHtXH" fullword
    $s622  = "certificateauthority" fullword
    $s656  = "191128154500Z0A1" fullword
    $s663  = "timerWithTimeInterval" fullword
    $s666  = "9allocatorIcEEEC1ERKS5" fullword
    $s676  = "AuthorizationFree" fullword
    $s696  = "UHAWAVAUATSPILuI" fullword
    $s723  = "convertBoolToObjCBoolyAA0eF0VSbF" fullword
    $s766  = "withIntermediateDirectories" fullword
    $s767  = "constructInstance" fullword
    $s775  = "characterIsMember" fullword
    $s784  = "NSPropertyListSerialization" fullword
    $s785  = "MacKeeperPrivilegedHelper" fullword
    $s789  = "conformsToProtocol" fullword
    $s818  = "allocBatchP11objc" fullword
    $s819  = "RGp0SARARARARARA" fullword
    $s824  = "initWithHelperID" fullword
    $s832  = "gSearchProviderUrl" fullword
    $s834  = "dictionaryWithContentsOfFile" fullword
    $s835  = "initWithContentsOfURL" fullword
    $s836  = "getInitializedObjCClass" fullword
    $s838  = "IORegistryEntryGetParentEntry" fullword
    $s847  = "NSAssertionHandler" fullword
    $s852  = "createDirectoryAtURL" fullword
    $s853  = "ZBSystemInformation" fullword
    $s861  = "getRequiredClass" fullword
    $s864  = "autoreleasePoolPushv" fullword
    $s871  = "setHTTPShouldHandleCookies" fullword
    $s872  = "lengthOfBytesUsingEncoding" fullword
    $s876  = "cancelButtonTitle" fullword
    $s877  = "systemFontOfSize" fullword
    $s879  = "stringWithUTF8String" fullword
    $s881  = "numberWithUnsignedLong" fullword
    $s888  = "numberWithDouble" fullword
    $s893  = "expectedContentLength" fullword
    $s894  = "objectForKeyP11objc" fullword
    $s896  = "kCFCoreFoundationVersionNumber" fullword
    $s899  = "fastIndexForKnownKey" fullword
    $s908  = "CFRunLoopGetMain" fullword
    $s916  = "isItemExpandable" fullword
    $s919  = "completionHandler" fullword
    $s923  = "substringToIndex" fullword
    $s929  = "dataTaskWithRequest" fullword
    $s930  = "enumerateObjectsUsingBlock" fullword
    $s935  = "NSDraggingSession" fullword
    $s937  = "NSUndoManagerProxy" fullword
    $s938  = "TpEQULved3Ly7GqqbjLfo6hqMSo" fullword
    $s941  = "timeIntervalSinceDate" fullword
    $s949  = "NSDistributedNotificationCenter" fullword
    $s959  = "autoreleasepoolPK11mach" fullword
    $s961  = "setStandardInput" fullword
    $s962  = "ASASASASASASASASASASB" fullword
    $s969  = "selectorPFP11objc" fullword
    $s993  = "applicationWillUnhide" fullword
    $s994  = "convertObjCBoolToBoolFVS" fullword
    $s995  = "applicationDidResignActive" fullword
    $s997  = "CSGetLocalIdentityAuthority" fullword
    $s998  = "userInterfaceIdiom" fullword
    $s1000 = "k7kBkQkpkkkkkkkkkkflmllllll" fullword
    $s1001 = "shouldDragDocumentWithEvent" fullword
    $s1007 = "NSOperationQueue" fullword
    $s1021 = "AudioConverterGetProperty" fullword
    $s1025 = "NetworkExtension" fullword
    $s1073 = "invalidateShadow" fullword
    $s1074 = "numberWithUnsignedInt" fullword
    $s1081 = "CGContextFillPath" fullword
    $s1087 = "ZL16scanMangledFieldRPKcS0" fullword
    $s1091 = "fileHandleForWriting" fullword
    $s1093 = "ContiguousaB0Vy7ElementQzGz" fullword
    $s1098 = "IOCreatePlugInInterfaceForService" fullword
    $s1100 = "IORegistryEntryFromPath" fullword
    $s1102 = "CGContextFillRect" fullword
    $s1113 = "scheduledTimerWithTimeInterval" fullword
    $s1130 = "Dfllononqpqpsrr2" fullword
    $s1135 = "N4laya11JSCFunctionIPFvllEEE" fullword
    $s1143 = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s1155 = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s1189 = "NSMutableURLRequest" fullword
    $s1208 = "N5boost9exceptionE" fullword
    $s1212 = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s1214 = "15mutex6unlockEv" fullword
    $s1216 = "ZTSN5boost18thread" fullword
    $s1255 = "18numpunctIcE12do" fullword
    $s1262 = "UHAWAVAUATSH8IILg" fullword
    $s1266 = "IOServiceTerminate" fullword
    $s1271 = "CFNumberGetValue" fullword
    $s1295 = "CFBundleShortVersionString" fullword
    $s1300 = "insertStatisticEvent" fullword
    $s1315 = "KGCustomMainWindowView" fullword
    $s1321 = "previousblockhash" fullword
    $s1336 = "NSRunningApplication" fullword
    $s1349 = "ZN5boost19thread" fullword
    $s1351 = "ZN11WalletModel20getAddressTableModelEv" fullword
    $s1358 = "N14LoggingHelpers13WebLogMessageE" fullword
    $s1366 = "didEndDisplayingHeaderView" fullword
    $s1368 = "iTunesSupportMaxVersion" fullword
    $s1369 = "didPresentAlertView" fullword
    $s1370 = "2numBlocksChanged" fullword
    $s1379 = "s8Dispatch0A4TimeVMa" fullword
    $s1382 = "deletedMethodError" fullword
    $s1389 = "componentsJoinedByString" fullword
    $s1399 = "delegateHandlesKey" fullword
    $s1414 = "NSStringPboardType" fullword
    $s1417 = "fileHandleForReading" fullword
    $s1421 = "210412223435Z0V1" fullword
    $s1437 = "backingScaleFactor" fullword
    $s1438 = "NSSharingServicePicker" fullword
    $s1439 = "operatingSystemVersionString" fullword
    $s1460 = "IOPlatformExpertDevice" fullword
    $s1461 = "numberWithUnsignedInteger" fullword
    $s1463 = "RARARARARARARARARARAZAp" fullword
    $s1467 = "kSecMatchLimitAll" fullword
    $s1469 = "applicationDockMenu" fullword
    $s1472 = "NSLayoutConstraint" fullword
    $s1474 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1491 = "formattedMetadata" fullword
    $s1493 = "clickedButtonAtIndex" fullword
    $s1504 = "viewForHeaderInSection" fullword
    $s1517 = "getMethodDescription" fullword
    $s1518 = "NSURLSessionDataTask" fullword
    $s1519 = "setIsAccessibilityElement" fullword
    $s1529 = "ponponqqtsrtsruuxwvwvyy" fullword
    $s1530 = "kUMPADUserDefaultKeyForStatisticsDisplayTimes" fullword
    $s1531 = "CFStreamCreatePairWithSocket" fullword
    $s1546 = "connectionRequired" fullword
    $s1557 = "JSValueMakeBoolean" fullword
    $s1560 = "EXUa2Kc9Qd9ysfHNqqIFg" fullword
    $s1570 = "replacementString" fullword
    $s1581 = "encodeURIComponent" fullword
    $s1583 = "CGImageSourceGetCount" fullword
    $s1587 = "otherButtonTitles" fullword
    $s1608 = "ZL20fixStringForCoreDataP11objc" fullword
    $s1610 = "127clEvE15obfuscated" fullword
    $s1611 = "didRegisterForRemoteNotificationsWithDeviceToken" fullword
    $s1613 = "ARARARARARARARARARARARARARARARARARARARBRB" fullword
    $s1617 = "SCNetworkReachabilityUnscheduleFromRunLoop" fullword
    $s1618 = "kMKNotificationActionReviewActionIdentifier" fullword
    $s1620 = "initWithSuiteName" fullword
    $s1626 = "NSDistantObjectRequest" fullword
    $s1638 = "MBRoundProgressView" fullword
    $s1643 = "setAllowedFileTypes" fullword
    $s1655 = "setInstanceVariableP11objc" fullword
    $s1658 = "imageWithCGImage" fullword
    $s1678 = "SSS10FoundationE19" fullword
    $s1683 = "setCanChooseDirectories" fullword
    $s1684 = "ARCLiteIndexedSubscripting" fullword
    $s1703 = "AC0D3QoSVAC0D13WorkItemFlagsVyyXBtF" fullword
    $s1714 = "NSJSONSerialization" fullword
    $s1727 = "UBRARARARARARARARARARARARARARARARARARARBRB" fullword
    $s1731 = "downloadTaskWithRequest" fullword
    $s1735 = "UHAWAVAUATSHHIH5M" fullword
    $s1745 = "IOServiceGetMatchingServices" fullword
    $s1748 = "ZNSt6vectorIP22OVSServer" fullword
    $s1753 = "systemVersionString" fullword
    $s1761 = "runningApplicationWithProcessIdentifier" fullword
    $s1770 = "certificationauthority" fullword
    $s1774 = "connectionDidFinishLoading" fullword
    $s1776 = "collectingEnabled" fullword
    $s1784 = "generationComplete" fullword
    $s1796 = "caseInsensitiveCompare" fullword
    $s1800 = "E1ELxHXLHPHDLPAHH" fullword
    $s1811 = "stringWithCapacity" fullword
    $s1817 = "setRolloverImage" fullword
    $s1823 = "totalBytesExpectedToSend" fullword
    $s1828 = "registerClassPair" fullword
    $s1832 = "200521020415Z0P1" fullword
    $s1851 = "setTimeoutIntervalForResource" fullword
    $s1856 = "UIApplicationDelegate" fullword

  condition:
    ((#s0 <= 1.5)
      and ((#s1 <= 1.5)
        and ((#s2 <= 0.5)
          and ((#s3 <= 1.0)
            and ((#s4 <= 0.5)
              and ((#s5 <= 1.5)
                and ((#s6 <= 1.5)
                  and ((#s7 <= 1.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 0.5)
                        and ((#s10 <= 0.5)
                          and ((#s11 <= 0.5)
                            and ((#s12 <= 0.5)
                              and ((#s13 <= 1.5)
                                and ((#s14 <= 0.5)
                                  and ((#s15 <= 0.5)
                                    and ((#s16 <= 0.5)
                                      and ((#s17 <= 0.5)
                                        and ((#s18 <= 0.5)
                                          and ((#s19 <= 0.5)
                                            and ((#s20 <= 0.5)
                                              and ((#s21 <= 0.5)
                                                and ((#s22 <= 0.5)
                                                  and ((#s23 <= 0.5)
                                                    and ((#s24 <= 0.5)
                                                      and ((#s25 <= 0.5)
                                                        and ((#s26 <= 0.5)
                                                          and ((#s27 <= 0.5)
                                                            and ((#s28 <= 0.5)
                                                              and ((#s29 <= 1.5)
                                                                and ((#s30 <= 0.5)
                                                                  and ((#s31 <= 0.5)
                                                                    and ((#s32 <= 0.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s34 <= 0.5)
                                                                          and ((#s35 <= 0.5)
                                                                            and ((#s36 <= 0.5)
                                                                              and ((#s37 <= 1.5)
                                                                                and ((#s38 <= 1.5)
                                                                                  and ((#s39 <= 0.5)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 0.5)
                                                                                              and ((#s45 <= 2.0)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 0.5)
                                                                                                    and ((#s48 <= 0.5)
                                                                                                      and ((#s49 <= 0.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 0.5)
                                                                                                            and ((#s52 <= 0.5)
                                                                                                              and ((#s53 <= 1.5)
                                                                                                                and ((#s54 <= 0.5)
                                                                                                                  and ((#s55 <= 1.0)
                                                                                                                    and ((#s56 <= 0.5)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 1.0)
                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s66 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((#s68 <= 0.5)
                                                                                                                                              and ((#s69 <= 1.5)
                                                                                                                                                and ((#s70 <= 0.5)
                                                                                                                                                  and ((#s71 <= 1.5)
                                                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                                                      and ((#s73 <= 0.5)
                                                                                                                                                        and ((#s74 <= 1.0)
                                                                                                                                                          and ((#s75 <= 0.5)
                                                                                                                                                            and ((#s76 <= 0.5)
                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                and ((#s78 <= 0.5)
                                                                                                                                                                  and ((#s79 <= 0.5)
                                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                                      and ((#s81 <= 0.5)
                                                                                                                                                                        and ((#s82 <= 1.0)
                                                                                                                                                                          and ((#s83 <= 0.5)
                                                                                                                                                                            and ((#s84 <= 0.5)
                                                                                                                                                                              and ((#s85 <= 0.5)
                                                                                                                                                                                and ((#s86 <= 0.5)
                                                                                                                                                                                  and ((#s87 <= 0.5)
                                                                                                                                                                                    and ((#s88 <= 0.5)
                                                                                                                                                                                      and ((#s89 <= 0.5)
                                                                                                                                                                                        and ((#s90 <= 0.5)
                                                                                                                                                                                          and ((#s91 <= 0.5)
                                                                                                                                                                                            and ((filesize <= 49020.0)
                                                                                                                                                                                              and ((#s93 <= 0.5)
                                                                                                                                                                                                and ((#s94 <= 1.0)
                                                                                                                                                                                                  and ((#s95 <= 0.5)
                                                                                                                                                                                                    and ((#s96 <= 0.5)
                                                                                                                                                                                                      and ((#s97 <= 0.5)
                                                                                                                                                                                                        and ((#s98 <= 0.5)
                                                                                                                                                                                                          and ((#s99 <= 2.0)
                                                                                                                                                                                                            and ((#s100 <= 0.5)
                                                                                                                                                                                                              and ((#s101 <= 1.5)
                                                                                                                                                                                                                and ((#s102 <= 0.5)
                                                                                                                                                                                                                  and ((#s103 <= 2.0)
                                                                                                                                                                                                                    and ((#s104 <= 0.5)
                                                                                                                                                                                                                      and ((#s105 <= 0.5)
                                                                                                                                                                                                                        and ((#s106 <= 1.0)
                                                                                                                                                                                                                          and ((#s107 <= 0.5)
                                                                                                                                                                                                                            and ((filesize > 4198.0)
                                                                                                                                                                                                                              and ((#s110 <= 0.5)
                                                                                                                                                                                                                                and ((#s111 <= 1.5)
                                                                                                                                                                                                                                  and ((#s112 <= 0.5)
                                                                                                                                                                                                                                    and ((#s113 <= 1.0)
                                                                                                                                                                                                                                      and ((#s114 <= 0.5)
                                                                                                                                                                                                                                        and ((#s53 <= 0.5)
                                                                                                                                                                                                                                          and ((#s116 <= 0.5)
                                                                                                                                                                                                                                            and ((#s117 <= 0.5)
                                                                                                                                                                                                                                              and ((#s118 <= 1.0)
                                                                                                                                                                                                                                                and ((#s119 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s120 <= 1.0)
                                                                                                                                                                                                                                                    and ((#s121 <= 1.5)
                                                                                                                                                                                                                                                      and ((#s122 <= 0.5)
                                                                                                                                                                                                                                                        and ((#s123 <= 1.5)
                                                                                                                                                                                                                                                          and ((#s124 <= 0.5)
                                                                                                                                                                                                                                                            and ((#s125 <= 1.0)
                                                                                                                                                                                                                                                              and ((filesize > 4236.0)
                                                                                                                                                                                                                                                                and ((#s128 <= 1.0)
                                                                                                                                                                                                                                                                  and ((filesize <= 5196.0)
                                                                                                                                                                                                                                                                    and ((filesize > 5152.0)
                                                                                                                                                                                                                                                                    ) or (filesize > 5196.0)
                                                                                                                                                                                                                                                                    and ((filesize <= 16380.0)
                                                                                                                                                                                                                                                                      and ((filesize <= 12526.0)
                                                                                                                                                                                                                                                                        and ((filesize > 8946.0)
                                                                                                                                                                                                                                                                          and ((filesize <= 8962.0)
                                                                                                                                                                                                                                                                          )) or (filesize > 12526.0)
                                                                                                                                                                                                                                                                        and ((#s140 <= 0.5)
                                                                                                                                                                                                                                                                          and ((filesize <= 12558.0)
                                                                                                                                                                                                                                                                          ))) or (filesize > 16380.0)
                                                                                                                                                                                                                                                                      and ((filesize <= 16494.0)
                                                                                                                                                                                                                                                                        and ((#s146 <= 1.0)
                                                                                                                                                                                                                                                                          and ((filesize > 16436.0)
                                                                                                                                                                                                                                                                          ) or (#s146 > 1.0)
                                                                                                                                                                                                                                                                        ) or (filesize > 16494.0)
                                                                                                                                                                                                                                                                        and ((#s151 <= 0.5)
                                                                                                                                                                                                                                                                          and ((#s152 <= 1.0)
                                                                                                                                                                                                                                                                            and ((#s153 <= 0.5)
                                                                                                                                                                                                                                                                              and ((#s154 <= 3.0)
                                                                                                                                                                                                                                                                                and ((filesize <= 26140.0)
                                                                                                                                                                                                                                                                                  and ((#s156 <= 0.5)
                                                                                                                                                                                                                                                                                    and ((filesize <= 25140.0)
                                                                                                                                                                                                                                                                                      and ((filesize <= 20788.0)
                                                                                                                                                                                                                                                                                        and ((filesize > 18982.0)
                                                                                                                                                                                                                                                                                          and ((filesize <= 19072.0)
                                                                                                                                                                                                                                                                                          )) or (filesize > 20788.0)
                                                                                                                                                                                                                                                                                        and ((filesize <= 20832.0)
                                                                                                                                                                                                                                                                                          or (filesize > 20832.0)
                                                                                                                                                                                                                                                                                          and ((#s166 <= 1.0)
                                                                                                                                                                                                                                                                                            and ((filesize <= 21672.0)
                                                                                                                                                                                                                                                                                              and ((filesize <= 21624.0)
                                                                                                                                                                                                                                                                                                and ((filesize <= 21332.0)
                                                                                                                                                                                                                                                                                                  and ((filesize <= 21250.0)
                                                                                                                                                                                                                                                                                                    and ((filesize > 21020.0)
                                                                                                                                                                                                                                                                                                      and ((filesize <= 21056.0)
                                                                                                                                                                                                                                                                                                      )) or (filesize > 21250.0)
                                                                                                                                                                                                                                                                                                  )) or (filesize > 21624.0)
                                                                                                                                                                                                                                                                                              ))))) or (filesize > 25140.0)
                                                                                                                                                                                                                                                                                      and ((filesize <= 25284.0)
                                                                                                                                                                                                                                                                                        or (filesize > 25284.0)
                                                                                                                                                                                                                                                                                        and ((filesize > 26044.0)
                                                                                                                                                                                                                                                                                        )))) or (filesize > 26140.0)
                                                                                                                                                                                                                                                                                  and ((filesize > 38116.0)
                                                                                                                                                                                                                                                                                    and ((filesize <= 38360.0)
                                                                                                                                                                                                                                                                                    )))))))))))))))))))))) or (#s53 > 0.5)
                                                                                                                                                                                                                                          and ((filesize > 27692.0)
                                                                                                                                                                                                                                          ))))) or (#s111 > 1.5)
                                                                                                                                                                                                                                )))))) or (#s104 > 0.5)
                                                                                                                                                                                                                    )))))))))))) or (filesize > 49020.0)
                                                                                                                                                                                              and ((#s122 <= 0.5)
                                                                                                                                                                                                and ((#s231 <= 0.5)
                                                                                                                                                                                                  and ((#s95 <= 0.5)
                                                                                                                                                                                                    and ((filesize <= 50174.5)
                                                                                                                                                                                                      and ((#s234 <= 0.5)
                                                                                                                                                                                                        and ((#s104 <= 0.5)
                                                                                                                                                                                                          and ((filesize > 50006.0)
                                                                                                                                                                                                            and ((filesize <= 50114.0)
                                                                                                                                                                                                              and ((filesize <= 50062.0)
                                                                                                                                                                                                              ) or (filesize > 50114.0)
                                                                                                                                                                                                            )) or (#s104 > 0.5)
                                                                                                                                                                                                        ) or (#s234 > 0.5)
                                                                                                                                                                                                      ) or (filesize > 50174.5)
                                                                                                                                                                                                      and ((#s245 <= 0.5)
                                                                                                                                                                                                        and ((#s246 <= 0.5)
                                                                                                                                                                                                          and ((#s247 <= 1.0)
                                                                                                                                                                                                            and ((#s248 <= 0.5)
                                                                                                                                                                                                              and ((#s249 <= 0.5)
                                                                                                                                                                                                                and ((#s250 <= 1.0)
                                                                                                                                                                                                                  and ((#s102 <= 0.5)
                                                                                                                                                                                                                    and ((#s118 <= 1.0)
                                                                                                                                                                                                                      and ((#s253 <= 1.0)
                                                                                                                                                                                                                        and ((#s254 <= 2.0)
                                                                                                                                                                                                                          and ((#s93 <= 0.5)
                                                                                                                                                                                                                            and ((#s53 <= 0.5)
                                                                                                                                                                                                                              and ((#s166 <= 0.5)
                                                                                                                                                                                                                                and ((#s258 <= 1.0)
                                                                                                                                                                                                                                  and ((#s259 <= 0.5)
                                                                                                                                                                                                                                    and ((#s260 <= 1.0)
                                                                                                                                                                                                                                      and ((#s261 <= 0.5)
                                                                                                                                                                                                                                        and ((#s262 <= 0.5)
                                                                                                                                                                                                                                          and ((#s121 <= 0.5)
                                                                                                                                                                                                                                            and ((#s124 <= 1.0)
                                                                                                                                                                                                                                              and ((#s265 <= 2.5)
                                                                                                                                                                                                                                                and ((#s266 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s267 <= 0.5)
                                                                                                                                                                                                                                                    and ((#s268 <= 0.5)
                                                                                                                                                                                                                                                      and ((#s269 <= 0.5)
                                                                                                                                                                                                                                                        and ((#s270 <= 1.5)
                                                                                                                                                                                                                                                          and ((#s94 <= 1.0)
                                                                                                                                                                                                                                                            and ((#s272 <= 0.5)
                                                                                                                                                                                                                                                              and ((#s273 <= 1.0)
                                                                                                                                                                                                                                                                and ((#s274 <= 0.5)
                                                                                                                                                                                                                                                                  and ((#s275 <= 1.0)
                                                                                                                                                                                                                                                                    and ((#s276 <= 1.0)
                                                                                                                                                                                                                                                                      and ((#s277 <= 0.5)
                                                                                                                                                                                                                                                                        and ((#s278 <= 0.5)
                                                                                                                                                                                                                                                                          and ((#s279 <= 0.5)
                                                                                                                                                                                                                                                                            and ((#s280 <= 0.5)
                                                                                                                                                                                                                                                                              and ((#s123 <= 0.5)
                                                                                                                                                                                                                                                                                and ((#s110 <= 0.5)
                                                                                                                                                                                                                                                                                  and ((#s156 <= 0.5)
                                                                                                                                                                                                                                                                                    and ((#s112 <= 0.5)
                                                                                                                                                                                                                                                                                      and ((#s285 <= 0.5)
                                                                                                                                                                                                                                                                                        and ((#s117 <= 0.5)
                                                                                                                                                                                                                                                                                          and ((#s287 <= 0.5)
                                                                                                                                                                                                                                                                                            and ((#s288 <= 0.5)
                                                                                                                                                                                                                                                                                              and ((#s105 <= 0.5)
                                                                                                                                                                                                                                                                                                and ((#s97 <= 1.0)
                                                                                                                                                                                                                                                                                                  and ((#s291 <= 0.5)
                                                                                                                                                                                                                                                                                                    and ((#s292 <= 1.0)
                                                                                                                                                                                                                                                                                                      and ((#s293 <= 0.5)
                                                                                                                                                                                                                                                                                                        and ((#s294 <= 0.5)
                                                                                                                                                                                                                                                                                                          and ((#s295 <= 0.5)
                                                                                                                                                                                                                                                                                                            and ((#s128 <= 1.0)
                                                                                                                                                                                                                                                                                                              and ((filesize <= 173138.0)
                                                                                                                                                                                                                                                                                                                and ((filesize <= 50238.0)
                                                                                                                                                                                                                                                                                                                  and ((filesize > 50178.5)
                                                                                                                                                                                                                                                                                                                  ) or (filesize > 50238.0)
                                                                                                                                                                                                                                                                                                                  and ((filesize <= 100238.0)
                                                                                                                                                                                                                                                                                                                    and ((filesize <= 99224.0)
                                                                                                                                                                                                                                                                                                                      and ((filesize > 71036.0)
                                                                                                                                                                                                                                                                                                                        and ((filesize <= 71394.0)
                                                                                                                                                                                                                                                                                                                          and ((filesize <= 71216.0)
                                                                                                                                                                                                                                                                                                                            and ((filesize <= 71180.0)
                                                                                                                                                                                                                                                                                                                            ) or (filesize > 71216.0)
                                                                                                                                                                                                                                                                                                                          ))) or (filesize > 99224.0)
                                                                                                                                                                                                                                                                                                                    ))) or (filesize > 173138.0)
                                                                                                                                                                                                                                                                                                                and ((filesize <= 173876.0)
                                                                                                                                                                                                                                                                                                                  or (filesize > 173876.0)
                                                                                                                                                                                                                                                                                                                  and ((filesize > 457316.0)
                                                                                                                                                                                                                                                                                                                    and ((filesize <= 464060.0)
                                                                                                                                                                                                                                                                                                                      or (filesize > 464060.0)
                                                                                                                                                                                                                                                                                                                      and ((filesize <= 624454.0)
                                                                                                                                                                                                                                                                                                                        and ((filesize > 615352.0)
                                                                                                                                                                                                                                                                                                                        ) or (filesize > 624454.0)
                                                                                                                                                                                                                                                                                                                        and ((filesize > 1641233.5)
                                                                                                                                                                                                                                                                                                                          and ((filesize <= 1933213.5)
                                                                                                                                                                                                                                                                                                                            and ((filesize <= 1882885.5)
                                                                                                                                                                                                                                                                                                                              and ((filesize <= 1763827.5)
                                                                                                                                                                                                                                                                                                                              ) or (filesize > 1882885.5)
                                                                                                                                                                                                                                                                                                                            ))))))))))))))))))))))))))))))))))))))))))))))))) or (#s93 > 0.5)
                                                                                                                                                                                                                            and ((#s53 <= 0.5)
                                                                                                                                                                                                                              and ((#s114 <= 0.5)
                                                                                                                                                                                                                                and ((#s166 <= 0.5)
                                                                                                                                                                                                                                  and ((#s378 <= 0.5)
                                                                                                                                                                                                                                    and ((#s379 <= 0.5)
                                                                                                                                                                                                                                      and ((#s262 <= 0.5)
                                                                                                                                                                                                                                        and ((#s94 <= 1.0)
                                                                                                                                                                                                                                          and ((#s291 <= 1.0)
                                                                                                                                                                                                                                            and ((#s117 <= 0.5)
                                                                                                                                                                                                                                              and ((#s293 <= 0.5)
                                                                                                                                                                                                                                                and ((#s93 > 1.5)
                                                                                                                                                                                                                                                  and ((#s112 <= 1.5)
                                                                                                                                                                                                                                                    and ((#s110 <= 0.5)
                                                                                                                                                                                                                                                      and ((filesize > 287642.0)
                                                                                                                                                                                                                                                        and ((#s93 <= 3.5)
                                                                                                                                                                                                                                                          and ((filesize <= 309258.0)
                                                                                                                                                                                                                                                          ))))))))))))))))))))))))))))))))))))))) or (#s84 > 0.5)
                                                                                                                                                                            )))) or (#s80 > 0.5)
                                                                                                                                                                      and ((#s107 <= 0.5)
                                                                                                                                                                        and ((#s99 > 1.0)
                                                                                                                                                                        )))) or (#s78 > 0.5)
                                                                                                                                                                ) or (#s77 > 0.5)
                                                                                                                                                                and ((#s439 <= 0.5)
                                                                                                                                                                  and ((#s80 > 1.5)
                                                                                                                                                                    and ((#s442 <= 0.5)
                                                                                                                                                                      and ((#s154 > 2.0)
                                                                                                                                                                        and ((#s445 <= 1.0)
                                                                                                                                                                        ))))))) or (#s75 > 0.5)
                                                                                                                                                          )) or (#s73 > 0.5)
                                                                                                                                                        and ((#s453 <= 0.5)
                                                                                                                                                          and ((#s123 <= 0.5)
                                                                                                                                                            and ((#s455 <= 0.5)
                                                                                                                                                              and ((#s456 <= 0.5)
                                                                                                                                                                and ((#s457 <= 0.5)
                                                                                                                                                                  and ((#s73 <= 1.5)
                                                                                                                                                                    and ((#s459 <= 1.0)
                                                                                                                                                                      and ((#s460 <= 0.5)
                                                                                                                                                                        and ((#s121 <= 1.0)
                                                                                                                                                                          and ((#s87 <= 0.5)
                                                                                                                                                                            and ((#s463 <= 0.5)
                                                                                                                                                                              and ((#s295 <= 0.5)
                                                                                                                                                                                and ((#s465 <= 0.5)
                                                                                                                                                                                  and ((#s466 <= 1.0)
                                                                                                                                                                                    and ((#s467 <= 0.5)
                                                                                                                                                                                      and ((#s97 <= 0.5)
                                                                                                                                                                                        and ((#s469 <= 0.5)
                                                                                                                                                                                          and ((#s288 <= 0.5)
                                                                                                                                                                                            and ((#s122 <= 0.5)
                                                                                                                                                                                              and ((#s94 <= 1.0)
                                                                                                                                                                                                and ((#s77 <= 1.0)
                                                                                                                                                                                                  and ((#s114 > 0.5)
                                                                                                                                                                                                    and ((filesize > 1544012.5)
                                                                                                                                                                                                    ))))))))))))))))))))))))) or (#s71 > 1.5)
                                                                                                                                                    and ((#s245 > 1.0)
                                                                                                                                                    )) or (#s70 > 0.5)
                                                                                                                                                ) or (#s69 > 1.5)
                                                                                                                                              ) or (#s68 > 0.5)
                                                                                                                                              and ((#s117 <= 0.5)
                                                                                                                                                and ((#s248 <= 0.5)
                                                                                                                                                  and ((#s68 <= 2.5)
                                                                                                                                                    and ((filesize <= 25456.0)
                                                                                                                                                      or (filesize > 25456.0)
                                                                                                                                                      and ((filesize > 622711.5)
                                                                                                                                                      ))))))) or (#s66 > 0.5)
                                                                                                                                          and ((#s100 > 2.0)
                                                                                                                                          ))) or (#s64 > 0.5)
                                                                                                                                    ) or (#s63 > 0.5)
                                                                                                                                  ) or (#s62 > 1.0)
                                                                                                                                ) or (#s61 > 0.5)
                                                                                                                                and ((#s525 <= 0.5)
                                                                                                                                  and ((#s526 > 1.0)
                                                                                                                                  ))) or (#s60 > 0.5)
                                                                                                                            )) or (#s58 > 0.5)
                                                                                                                          and ((#s128 <= 3.0)
                                                                                                                            and ((#s533 <= 0.5)
                                                                                                                              and ((#s534 <= 0.5)
                                                                                                                                and ((#s535 <= 0.5)
                                                                                                                                  and ((#s536 <= 0.5)
                                                                                                                                    and ((#s537 <= 0.5)
                                                                                                                                      and ((#s105 <= 0.5)
                                                                                                                                        and ((#s274 > 0.5)
                                                                                                                                        ))))))) or (#s128 > 3.0)
                                                                                                                            and ((#s90 <= 1.0)
                                                                                                                              and ((#s72 > 1.0)
                                                                                                                                and ((#s279 > 5.0)
                                                                                                                                ))))) or (#s57 > 0.5)
                                                                                                                      ) or (#s56 > 0.5)
                                                                                                                      and ((#s455 <= 0.5)
                                                                                                                        and ((#s114 <= 0.5)
                                                                                                                          and ((#s558 <= 0.5)
                                                                                                                            and ((#s66 > 0.5)
                                                                                                                              and ((#s90 > 0.5)
                                                                                                                              )))))) or (#s55 > 1.0)
                                                                                                                  )) or (#s53 > 1.5)
                                                                                                                and ((#s248 <= 0.5)
                                                                                                                  and ((filesize <= 501929.5)
                                                                                                                    and ((#s536 <= 0.5)
                                                                                                                      and ((#s53 <= 2.5)
                                                                                                                        and ((#s117 <= 0.5)
                                                                                                                          and ((#s73 <= 1.0)
                                                                                                                            and ((#s280 <= 0.5)
                                                                                                                              and ((filesize > 380977.5)
                                                                                                                              ))))))))) or (#s52 > 0.5)
                                                                                                              and ((#s586 <= 0.5)
                                                                                                                and ((#s587 <= 1.5)
                                                                                                                  and ((#s123 <= 1.5)
                                                                                                                    and ((#s245 <= 0.5)
                                                                                                                      and ((#s590 <= 0.5)
                                                                                                                        and ((#s591 <= 1.0)
                                                                                                                          and ((#s592 <= 0.5)
                                                                                                                            and ((#s269 <= 1.0)
                                                                                                                              and ((#s594 <= 0.5)
                                                                                                                                and ((#s595 <= 0.5)
                                                                                                                                  and ((#s258 <= 1.0)
                                                                                                                                    and ((#s112 <= 1.0)
                                                                                                                                      and ((filesize <= 34000.0)
                                                                                                                                        and ((#s74 <= 1.0)
                                                                                                                                          and ((#s94 <= 1.0)
                                                                                                                                            and ((#s455 <= 1.0)
                                                                                                                                              and ((#s65 <= 1.5)
                                                                                                                                                and ((#s558 <= 0.5)
                                                                                                                                                  and ((#s73 <= 1.5)
                                                                                                                                                    and ((#s83 > 1.0)
                                                                                                                                                    ) or (#s73 > 1.5)
                                                                                                                                                  )) or (#s65 > 1.5)
                                                                                                                                                and ((#s93 <= 1.0)
                                                                                                                                                  and ((#s128 <= 1.0)
                                                                                                                                                    and ((#s612 <= 0.5)
                                                                                                                                                      and ((#s613 <= 0.5)
                                                                                                                                                        and ((#s614 <= 0.5)
                                                                                                                                                          and ((#s114 <= 0.5)
                                                                                                                                                            and ((#s616 <= 0.5)
                                                                                                                                                              and ((filesize <= 27272.0)
                                                                                                                                                                and ((#s68 <= 0.5)
                                                                                                                                                                  and ((#s294 <= 1.0)
                                                                                                                                                                    and ((#s73 <= 1.0)
                                                                                                                                                                      and ((#s59 <= 1.0)
                                                                                                                                                                        and ((#s622 <= 0.5)
                                                                                                                                                                          and ((#s85 <= 0.5)
                                                                                                                                                                            and ((filesize > 23824.0)
                                                                                                                                                                              and ((filesize <= 23920.0)
                                                                                                                                                                              ))) or (#s622 > 0.5)
                                                                                                                                                                        )))))) or (#s616 > 0.5)
                                                                                                                                                            ))) or (#s613 > 0.5)
                                                                                                                                                      ) or (#s612 > 0.5)
                                                                                                                                                    )) or (#s93 > 1.0)
                                                                                                                                                  and ((#s612 <= 0.5)
                                                                                                                                                    and ((#s59 <= 1.0)
                                                                                                                                                    ) or (#s612 > 0.5)
                                                                                                                                                  )))))) or (filesize > 34000.0)
                                                                                                                                        and ((#s248 <= 0.5)
                                                                                                                                          and ((#s94 <= 0.5)
                                                                                                                                            and ((#s72 <= 0.5)
                                                                                                                                              and ((#s110 <= 0.5)
                                                                                                                                                and ((#s460 <= 0.5)
                                                                                                                                                  and ((#s59 <= 1.0)
                                                                                                                                                    and ((#s656 <= 0.5)
                                                                                                                                                      and ((#s246 <= 0.5)
                                                                                                                                                        and ((#s61 <= 0.5)
                                                                                                                                                          and ((#s90 <= 0.5)
                                                                                                                                                            and ((#s275 <= 1.0)
                                                                                                                                                              and ((#s280 <= 0.5)
                                                                                                                                                                and ((#s87 <= 1.0)
                                                                                                                                                                  and ((#s663 <= 0.5)
                                                                                                                                                                    and ((#s65 <= 3.0)
                                                                                                                                                                      and ((#s272 <= 0.5)
                                                                                                                                                                        and ((#s666 <= 1.0)
                                                                                                                                                                          and ((#s124 <= 0.5)
                                                                                                                                                                            and ((#s114 <= 0.5)
                                                                                                                                                                              and ((filesize <= 69612.0)
                                                                                                                                                                                and ((#s93 <= 1.0)
                                                                                                                                                                                  and ((#s622 <= 0.5)
                                                                                                                                                                                    and ((#s117 <= 0.5)
                                                                                                                                                                                      and ((#s88 <= 1.0)
                                                                                                                                                                                        and ((#s73 <= 1.0)
                                                                                                                                                                                          and ((#s614 <= 0.5)
                                                                                                                                                                                            and ((#s676 <= 0.5)
                                                                                                                                                                                              and ((#s65 > 1.5)
                                                                                                                                                                                                and ((filesize <= 36984.0)
                                                                                                                                                                                                  and ((#s294 <= 1.0)
                                                                                                                                                                                                    and ((filesize > 36656.0)
                                                                                                                                                                                                    ))))))))) or (#s622 > 0.5)
                                                                                                                                                                                    and ((filesize > 59200.0)
                                                                                                                                                                                    ))) or (filesize > 69612.0)
                                                                                                                                                                                and ((#s53 <= 0.5)
                                                                                                                                                                                  and ((#s696 <= 0.5)
                                                                                                                                                                                    and ((#s231 <= 1.0)
                                                                                                                                                                                      and ((#s614 <= 0.5)
                                                                                                                                                                                        and ((filesize > 495712.0)
                                                                                                                                                                                          and ((filesize <= 509112.0)
                                                                                                                                                                                          ))))))))) or (#s666 > 1.0)
                                                                                                                                                                          and ((#s666 <= 3.0)
                                                                                                                                                                            and ((#s295 > 1.0)
                                                                                                                                                                            ))))))))))) or (#s246 > 0.5)
                                                                                                                                                        and ((#s723 <= 1.0)
                                                                                                                                                          and ((#s262 <= 0.5)
                                                                                                                                                            and ((#s249 <= 1.0)
                                                                                                                                                              and ((#s457 <= 1.0)
                                                                                                                                                                and ((#s270 <= 1.0)
                                                                                                                                                                  and ((#s246 <= 1.5)
                                                                                                                                                                    and ((filesize <= 374680.0)
                                                                                                                                                                      and ((#s622 <= 0.5)
                                                                                                                                                                        and ((#s97 <= 1.0)
                                                                                                                                                                          and ((#s124 <= 1.0)
                                                                                                                                                                            and ((#s93 <= 1.0)
                                                                                                                                                                            )))))))))))) or (#s656 > 0.5)
                                                                                                                                                      and ((filesize <= 189936.0)
                                                                                                                                                        and ((filesize > 58808.0)
                                                                                                                                                        )))))))))))) or (#s595 > 0.5)
                                                                                                                                ))) or (#s592 > 0.5)
                                                                                                                          )))) or (#s123 > 1.5)
                                                                                                                    and ((#s766 <= 0.5)
                                                                                                                      and ((#s767 <= 1.0)
                                                                                                                        and ((#s90 > 0.5)
                                                                                                                        )))) or (#s587 > 1.5)
                                                                                                                ))) or (#s51 > 0.5)
                                                                                                            and ((#s775 <= 1.0)
                                                                                                              and ((#s105 <= 1.0)
                                                                                                                and ((#s558 > 0.5)
                                                                                                                )))) or (#s50 > 0.5)
                                                                                                        ) or (#s49 > 0.5)
                                                                                                        and ((#s535 <= 0.5)
                                                                                                          and ((#s784 <= 1.0)
                                                                                                            and ((#s785 <= 1.0)
                                                                                                              and ((#s465 <= 0.5)
                                                                                                                and ((#s112 <= 1.0)
                                                                                                                  and ((#s83 <= 1.0)
                                                                                                                    and ((#s789 <= 0.5)
                                                                                                                      and ((#s97 > 0.5)
                                                                                                                        and ((#s61 <= 0.5)
                                                                                                                          and ((#s86 <= 0.5)
                                                                                                                            and ((#s85 <= 0.5)
                                                                                                                              and ((#s460 <= 1.0)
                                                                                                                                and ((#s378 <= 0.5)
                                                                                                                                  and ((filesize <= 41520.0)
                                                                                                                                    and ((#s94 <= 0.5)
                                                                                                                                      and ((#s73 > 1.0)
                                                                                                                                      )))))))))))) or (#s465 > 0.5)
                                                                                                                and ((#s128 <= 0.5)
                                                                                                                )) or (#s785 > 1.0)
                                                                                                            )) or (#s535 > 0.5)
                                                                                                          and ((#s87 <= 2.0)
                                                                                                            and ((#s818 <= 0.5)
                                                                                                              and ((#s819 > 0.5)
                                                                                                                and ((#s94 <= 4.0)
                                                                                                                  and ((#s277 > 0.5)
                                                                                                                    and ((#s824 > 0.5)
                                                                                                                    )) or (#s94 > 4.0)
                                                                                                                ))))))) or (#s47 > 0.5)
                                                                                                  ) or (#s46 > 0.5)
                                                                                                  and ((#s832 <= 1.0)
                                                                                                    and ((#s622 <= 0.5)
                                                                                                      and ((#s834 <= 0.5)
                                                                                                        and ((#s835 <= 0.5)
                                                                                                          and ((#s836 <= 1.0)
                                                                                                            and ((#s766 <= 0.5)
                                                                                                              and ((#s838 > 1.0)
                                                                                                                and ((#s51 <= 0.5)
                                                                                                                  and ((#s56 <= 0.5)
                                                                                                                  ))) or (#s766 > 0.5)
                                                                                                              and ((#s73 > 1.5)
                                                                                                                and ((#s847 <= 1.0)
                                                                                                                  and ((#s52 > 0.5)
                                                                                                                    and ((#s590 <= 0.5)
                                                                                                                      or (#s590 > 0.5)
                                                                                                                      and ((#s852 <= 0.5)
                                                                                                                        and ((#s853 > 1.0)
                                                                                                                        )))))))) or (#s835 > 0.5)
                                                                                                          and ((#s459 > 0.5)
                                                                                                            and ((#s861 > 1.5)
                                                                                                              and ((#s246 <= 0.5)
                                                                                                                and ((#s864 <= 0.5)
                                                                                                                  and ((#s94 > 2.0)
                                                                                                                  )))))) or (#s834 > 0.5)
                                                                                                        and ((#s107 <= 0.5)
                                                                                                          and ((#s871 <= 0.5)
                                                                                                            and ((#s872 <= 0.5)
                                                                                                              and ((#s73 > 1.5)
                                                                                                                and ((#s784 <= 1.0)
                                                                                                                  and ((#s876 <= 1.0)
                                                                                                                    and ((#s877 <= 0.5)
                                                                                                                      and ((#s72 <= 0.5)
                                                                                                                        and ((#s879 > 0.5)
                                                                                                                          and ((#s881 <= 0.5)
                                                                                                                          ))))))) or (#s872 > 0.5)
                                                                                                              and ((#s888 > 0.5)
                                                                                                              ))))) or (#s622 > 0.5)
                                                                                                      and ((#s893 <= 2.0)
                                                                                                        and ((#s894 <= 0.5)
                                                                                                          and ((#s107 <= 0.5)
                                                                                                            and ((#s896 <= 1.0)
                                                                                                              and ((#s52 > 0.5)
                                                                                                                and ((#s899 <= 0.5)
                                                                                                                  and ((#s54 <= 0.5)
                                                                                                                  ))) or (#s896 > 1.0)
                                                                                                              and ((#s466 <= 1.0)
                                                                                                              ))) or (#s894 > 0.5)
                                                                                                          and ((#s908 <= 1.0)
                                                                                                            and ((#s116 <= 1.0)
                                                                                                            ))) or (#s893 > 2.0)
                                                                                                      )) or (#s832 > 1.0)
                                                                                                  )) or (#s45 > 2.0)
                                                                                              ) or (#s44 > 0.5)
                                                                                              and ((#s916 <= 0.5)
                                                                                                and ((#s94 <= 0.5)
                                                                                                  and ((#s457 <= 0.5)
                                                                                                    and ((#s919 <= 0.5)
                                                                                                      and ((#s73 <= 1.5)
                                                                                                        or (#s73 > 1.5)
                                                                                                        and ((#s119 <= 0.5)
                                                                                                          and ((#s923 > 0.5)
                                                                                                            and ((#s467 > 0.5)
                                                                                                            )))) or (#s919 > 0.5)
                                                                                                      and ((#s929 <= 0.5)
                                                                                                        and ((#s930 > 0.5)
                                                                                                        )))) or (#s94 > 0.5)
                                                                                                  and ((#s935 <= 1.0)
                                                                                                    and ((#s879 <= 1.5)
                                                                                                      and ((#s937 <= 0.5)
                                                                                                        and ((#s938 <= 0.5)
                                                                                                          and ((filesize <= 71570.0)
                                                                                                            and ((#s457 <= 0.5)
                                                                                                              and ((#s941 <= 0.5)
                                                                                                                and ((#s66 <= 0.5)
                                                                                                                  and ((#s56 > 0.5)
                                                                                                                    and ((#s120 <= 0.5)
                                                                                                                      and ((#s463 <= 1.0)
                                                                                                                        and ((#s73 > 1.5)
                                                                                                                          and ((#s949 <= 1.0)
                                                                                                                          ))))) or (#s66 > 0.5)
                                                                                                                )))) or (#s938 > 0.5)
                                                                                                        ) or (#s937 > 0.5)
                                                                                                        and ((#s959 <= 1.5)
                                                                                                          and ((#s852 <= 0.5)
                                                                                                            and ((#s961 <= 0.5)
                                                                                                              and ((#s962 <= 0.5)
                                                                                                              ))) or (#s959 > 1.5)
                                                                                                          and ((#s52 > 0.5)
                                                                                                            and ((#s969 > 0.5)
                                                                                                            )))) or (#s879 > 1.5)
                                                                                                      and ((#s941 <= 1.0)
                                                                                                      )) or (#s935 > 1.0)
                                                                                                  )))) or (#s43 > 0.5)
                                                                                          ) or (#s42 > 0.5)
                                                                                          and ((#s231 <= 0.5)
                                                                                            and ((#s73 <= 1.5)
                                                                                              and ((#s89 <= 0.5)
                                                                                              ) or (#s73 > 1.5)
                                                                                              and ((#s65 <= 1.5)
                                                                                              )) or (#s231 > 0.5)
                                                                                            and ((filesize <= 20408.0)
                                                                                            ))) or (#s41 > 0.5)
                                                                                        and ((#s107 <= 1.0)
                                                                                        )) or (#s40 > 0.5)
                                                                                      and ((#s819 <= 0.5)
                                                                                        and ((#s993 <= 0.5)
                                                                                          and ((#s994 <= 0.5)
                                                                                            and ((#s995 <= 2.0)
                                                                                              and ((#s456 <= 1.0)
                                                                                                and ((#s997 <= 1.0)
                                                                                                  and ((#s998 <= 0.5)
                                                                                                    and ((#s48 <= 1.0)
                                                                                                      and ((#s1000 <= 0.5)
                                                                                                        and ((#s1001 <= 0.5)
                                                                                                          and ((#s87 <= 0.5)
                                                                                                            and ((#s117 <= 0.5)
                                                                                                              and ((#s71 <= 0.5)
                                                                                                                and ((#s85 <= 0.5)
                                                                                                                  and ((#s836 <= 0.5)
                                                                                                                    and ((#s1007 <= 0.5)
                                                                                                                      and ((#s558 <= 0.5)
                                                                                                                        and ((#s246 <= 0.5)
                                                                                                                          and ((#s245 <= 0.5)
                                                                                                                            and ((#s52 <= 0.5)
                                                                                                                              and ((#s97 <= 0.5)
                                                                                                                                and ((#s61 <= 0.5)
                                                                                                                                  and ((#s40 <= 2.5)
                                                                                                                                    and ((#s53 <= 0.5)
                                                                                                                                      and ((#s95 <= 0.5)
                                                                                                                                        and ((#s151 <= 0.5)
                                                                                                                                          and ((#s40 > 1.5)
                                                                                                                                            and ((#s110 <= 0.5)
                                                                                                                                              and ((#s1021 <= 0.5)
                                                                                                                                                and ((#s120 <= 0.5)
                                                                                                                                                  and ((#s124 <= 0.5)
                                                                                                                                                    and ((#s73 <= 0.5)
                                                                                                                                                      and ((#s1025 <= 1.0)
                                                                                                                                                        and ((#s152 <= 1.0)
                                                                                                                                                          and ((filesize > 19296.0)
                                                                                                                                                            and ((#s466 <= 1.0)
                                                                                                                                                              and ((#s74 <= 1.0)
                                                                                                                                                                and ((filesize <= 19830.0)
                                                                                                                                                                  or (filesize > 19830.0)
                                                                                                                                                                  and ((filesize > 538150.0)
                                                                                                                                                                    and ((filesize <= 624612.0)
                                                                                                                                                                    )))))))))))))))))))))))))))))) or (#s1001 > 0.5)
                                                                                                          and ((#s100 <= 1.0)
                                                                                                            and ((filesize <= 396668.0)
                                                                                                            ))) or (#s1000 > 0.5)
                                                                                                      ))) or (#s997 > 1.0)
                                                                                                )) or (#s995 > 2.0)
                                                                                              and ((#s1073 <= 0.5)
                                                                                                and ((#s1074 > 0.5)
                                                                                                )))) or (#s993 > 0.5)
                                                                                          and ((#s1007 <= 3.0)
                                                                                            and ((#s879 <= 0.5)
                                                                                              and ((#s1081 <= 0.5)
                                                                                              )))) or (#s819 > 0.5)
                                                                                        and ((#s120 <= 0.5)
                                                                                          and ((#s1087 <= 0.5)
                                                                                          )))) or (#s39 > 0.5)
                                                                                    and ((#s1091 <= 0.5)
                                                                                      and ((#s106 <= 1.0)
                                                                                        and ((#s1093 <= 0.5)
                                                                                          and ((#s46 <= 0.5)
                                                                                            and ((#s994 <= 0.5)
                                                                                              and ((filesize > 89304.0)
                                                                                                and ((#s1098 > 0.5)
                                                                                                  and ((#s1100 <= 0.5)
                                                                                                    and ((#s881 <= 0.5)
                                                                                                      and ((#s1102 > 0.5)
                                                                                                      )))))))) or (#s106 > 1.0)
                                                                                      ) or (#s1091 > 0.5)
                                                                                      and ((#s766 > 0.5)
                                                                                        and ((#s1113 > 0.5)
                                                                                          and ((#s120 > 1.5)
                                                                                            and ((#s107 <= 2.5)
                                                                                              and ((filesize > 182000.0)
                                                                                              ))))))) or (#s38 > 1.5)
                                                                                  and ((#s40 <= 2.5)
                                                                                    and ((#s121 <= 2.0)
                                                                                      and ((#s140 <= 0.5)
                                                                                        and ((#s888 <= 0.5)
                                                                                          and ((#s465 <= 3.5)
                                                                                            and ((#s67 <= 1.0)
                                                                                              and ((#s40 > 1.0)
                                                                                                and ((#s1130 <= 0.5)
                                                                                                  and ((#s466 <= 1.0)
                                                                                                    and ((#s85 > 0.5)
                                                                                                      and ((#s152 <= 1.0)
                                                                                                        and ((#s1135 <= 0.5)
                                                                                                          and ((#s85 <= 3.5)
                                                                                                          ) or (#s1135 > 0.5)
                                                                                                        ))) or (#s466 > 1.0)
                                                                                                    and ((filesize > 8760.0)
                                                                                                      and ((#s1143 <= 1.5)
                                                                                                        and ((#s1025 <= 1.0)
                                                                                                          and ((filesize <= 7578068.0)
                                                                                                            and ((filesize <= 479142.0)
                                                                                                              and ((filesize <= 26556.0)
                                                                                                              ) or (filesize > 479142.0)
                                                                                                              and ((#s1143 <= 0.5)
                                                                                                                and ((filesize <= 1132332.0)
                                                                                                                ) or (#s1143 > 0.5)
                                                                                                                and ((filesize <= 1348088.0)
                                                                                                                  and ((#s1155 <= 0.5)
                                                                                                                  ) or (filesize > 1348088.0)
                                                                                                                )))) or (#s1025 > 1.0)
                                                                                                          and ((filesize <= 14024.0)
                                                                                                            and ((filesize <= 12038.0)
                                                                                                              and ((filesize > 10528.0)
                                                                                                              )) or (filesize > 14024.0)
                                                                                                            and ((filesize <= 18120.0)
                                                                                                              and ((filesize <= 16072.0)
                                                                                                              ) or (filesize > 18120.0)
                                                                                                            ))) or (#s1143 > 1.5)
                                                                                                      ))) or (#s1130 > 0.5)
                                                                                                ))))))))) or (#s37 > 1.5)
                                                                                and ((#s105 > 1.0)
                                                                                )) or (#s36 > 0.5)
                                                                            ) or (#s35 > 0.5)
                                                                          ) or (#s34 > 0.5)
                                                                        ) or (#s33 > 0.5)
                                                                      ) or (#s32 > 0.5)
                                                                    ) or (#s31 > 0.5)
                                                                  ) or (#s30 > 0.5)
                                                                ) or (#s29 > 1.5)
                                                                and ((#s1189 <= 4.5)
                                                                )) or (#s28 > 0.5)
                                                            ) or (#s27 > 0.5)
                                                          ) or (#s26 > 0.5)
                                                        ) or (#s25 > 0.5)
                                                      ) or (#s24 > 0.5)
                                                    ) or (#s23 > 0.5)
                                                    and ((#s123 > 1.0)
                                                    )) or (#s22 > 0.5)
                                                ) or (#s21 > 0.5)
                                              ) or (#s20 > 0.5)
                                            ) or (#s19 > 0.5)
                                            and ((#s291 <= 0.5)
                                              and ((#s666 > 3.0)
                                                and ((#s614 <= 0.5)
                                                  and ((#s442 <= 0.5)
                                                    and ((#s1208 > 0.5)
                                                      and ((#s81 > 1.0)
                                                        and ((#s1212 > 1.0)
                                                          and ((#s1214 > 1.0)
                                                            and ((#s1216 > 1.0)
                                                            ))))) or (#s442 > 0.5)
                                                  ))))) or (#s18 > 0.5)
                                        ) or (#s17 > 0.5)
                                      ) or (#s16 > 0.5)
                                      and ((#s245 <= 0.5)
                                        and ((#s107 <= 0.5)
                                          and ((#s58 > 0.5)
                                          ) or (#s107 > 0.5)
                                        ) or (#s245 > 0.5)
                                      )) or (#s15 > 0.5)
                                  ) or (#s14 > 0.5)
                                ) or (#s13 > 1.5)
                                and ((#s558 <= 2.5)
                                  and ((#s66 <= 0.5)
                                    and ((#s58 <= 1.0)
                                    ) or (#s66 > 0.5)
                                    and ((#s16 <= 2.0)
                                      and ((#s872 <= 0.5)
                                      ) or (#s16 > 2.0)
                                    )))) or (#s12 > 0.5)
                              and ((#s469 > 1.0)
                              )) or (#s11 > 0.5)
                            and ((#s246 > 0.5)
                              and ((#s52 <= 0.5)
                              ))) or (#s10 > 0.5)
                        ) or (#s9 > 0.5)
                      ) or (#s8 > 0.5)
                    ) or (#s7 > 1.5)
                    and ((#s1255 <= 1.0)
                      and ((#s1091 <= 0.5)
                        and ((#s460 <= 0.5)
                          and ((#s66 <= 1.5)
                            and ((#s49 <= 0.5)
                              and ((#s291 <= 0.5)
                                and ((#s52 <= 0.5)
                                  and ((#s1262 <= 0.5)
                                    and ((#s85 <= 6.0)
                                      and ((#s53 <= 3.5)
                                        and ((#s258 <= 1.0)
                                          and ((#s1266 <= 0.5)
                                            and ((#s1073 <= 0.5)
                                              and ((#s247 <= 0.5)
                                                and ((#s463 <= 1.0)
                                                  and ((#s40 <= 1.0)
                                                    and ((#s1271 <= 1.0)
                                                    ) or (#s40 > 1.0)
                                                    and ((#s881 > 0.5)
                                                    ))) or (#s247 > 0.5)
                                              ) or (#s1073 > 0.5)
                                            )))))) or (#s52 > 0.5)
                                  and ((#s40 <= 1.0)
                                    and ((#s274 <= 0.5)
                                      and ((#s558 <= 0.5)
                                        and ((filesize <= 773352.0)
                                          and ((#s1266 > 0.5)
                                          )) or (#s558 > 0.5)
                                        and ((#s1271 > 1.0)
                                          and ((#s1295 > 0.5)
                                          ))) or (#s274 > 0.5)
                                    ) or (#s40 > 1.0)
                                    and ((#s100 <= 1.0)
                                      and ((#s1300 <= 1.0)
                                        and ((#s66 > 0.5)
                                        ) or (#s1300 > 1.0)
                                      ))))) or (#s49 > 0.5)
                              and ((#s1271 <= 1.0)
                                and ((#s72 > 0.5)
                                  and ((#s1300 > 0.5)
                                  ))))) or (#s460 > 0.5)
                          and ((#s1315 <= 4.5)
                            and ((#s61 <= 0.5)
                              and ((#s275 <= 1.0)
                                and ((#s97 <= 0.5)
                                  and ((#s39 > 0.5)
                                    and ((#s1321 <= 1.0)
                                      and ((#s245 <= 1.0)
                                        and ((#s39 <= 1.5)
                                        )) or (#s1321 > 1.0)
                                    )))) or (#s61 > 0.5)
                              and ((#s586 > 0.5)
                                and ((#s274 <= 4.5)
                                ))) or (#s1315 > 4.5)
                          )) or (#s1091 > 0.5)
                        and ((#s1336 <= 1.0)
                          and ((#s1091 > 1.5)
                            and ((#s766 > 1.0)
                            )) or (#s1336 > 1.0)
                        )) or (#s1255 > 1.0)
                      and ((#s107 <= 1.0)
                      ))) or (#s6 > 1.5)
                  and ((#s6 <= 3.5)
                    and ((#s110 <= 1.5)
                      or (#s110 > 1.5)
                      and ((#s1349 <= 16.0)
                        or (#s1349 > 16.0)
                        and ((#s1351 > 0.5)
                        ))))) or (#s5 > 1.5)
                and ((#s56 <= 0.5)
                  and ((#s61 > 0.5)
                    and ((#s1358 <= 0.5)
                      and ((#s879 <= 0.5)
                      ) or (#s1358 > 0.5)
                    )) or (#s56 > 0.5)
                  and ((#s80 > 2.0)
                  ))) or (#s4 > 0.5)
              and ((#s1366 <= 0.5)
                and ((#s95 <= 0.5)
                  and ((#s1368 <= 0.5)
                    and ((#s1369 <= 0.5)
                      and ((#s1370 <= 1.0)
                        and ((#s288 <= 1.0)
                          and ((#s784 <= 3.5)
                            and ((#s847 <= 1.0)
                              and ((#s39 <= 0.5)
                                and ((#s7 <= 1.0)
                                  and ((#s919 <= 3.5)
                                    and ((#s49 <= 0.5)
                                      and ((#s73 <= 1.5)
                                        and ((#s1379 <= 1.0)
                                          and ((#s466 <= 0.5)
                                            and ((#s76 <= 0.5)
                                              and ((#s1382 <= 1.0)
                                              ) or (#s76 > 0.5)
                                            ))) or (#s73 > 1.5)
                                        and ((#s89 <= 0.5)
                                          and ((#s1389 <= 0.5)
                                            and ((#s879 <= 0.5)
                                              and ((#s61 > 0.5)
                                                and ((#s262 <= 0.5)
                                                  and ((#s766 <= 0.5)
                                                  ) or (#s262 > 0.5)
                                                )) or (#s879 > 0.5)
                                              and ((#s105 <= 1.0)
                                                and ((#s1399 <= 0.5)
                                                  and ((#s277 <= 1.0)
                                                  ) or (#s1399 > 0.5)
                                                  and ((#s258 <= 1.0)
                                                    and ((filesize <= 38256.0)
                                                      or (filesize > 38256.0)
                                                      and ((#s61 > 0.5)
                                                      )) or (#s258 > 1.0)
                                                  )))) or (#s1389 > 0.5)
                                          )))) or (#s919 > 3.5)
                                    and ((#s1414 <= 0.5)
                                      and ((#s116 > 1.0)
                                        and ((#s1417 <= 0.5)
                                          and ((#s248 <= 1.0)
                                            and ((#s119 <= 0.5)
                                              and ((#s90 <= 0.5)
                                                and ((#s1421 <= 0.5)
                                                  and ((#s93 <= 1.0)
                                                    and ((#s834 > 0.5)
                                                    ))) or (#s90 > 0.5)
                                                and ((#s105 > 1.0)
                                                  and ((#s98 > 0.5)
                                                  ))))) or (#s1417 > 0.5)
                                        )))) or (#s7 > 1.0)
                                  and ((#s1437 <= 0.5)
                                    and ((#s1438 <= 1.0)
                                      and ((#s1439 <= 0.5)
                                        and ((#s49 <= 0.5)
                                          and ((#s294 <= 1.0)
                                            and ((#s1113 <= 0.5)
                                              and ((#s77 <= 27.5)
                                                and ((filesize > 118720.0)
                                                )) or (#s1113 > 0.5)
                                              and ((#s1336 > 1.0)
                                              )))) or (#s1439 > 0.5)
                                        and ((#s153 > 1.5)
                                        ))))) or (#s39 > 0.5)
                                and ((#s98 > 0.5)
                                  and ((#s1460 <= 0.5)
                                    and ((#s1461 <= 0.5)
                                      or (#s1461 > 0.5)
                                      and ((#s1463 <= 0.5)
                                      )) or (#s1460 > 0.5)
                                  ))) or (#s847 > 1.0)
                              and ((#s1467 <= 1.0)
                                and ((#s246 <= 0.5)
                                  and ((#s1469 > 0.5)
                                    and ((#s834 <= 0.5)
                                      and ((#s1472 > 1.0)
                                        and ((#s1474 <= 0.5)
                                          and ((#s277 > 0.5)
                                          ))) or (#s834 > 0.5)
                                      and ((#s86 > 1.5)
                                      )))) or (#s1467 > 1.0)
                                and ((#s919 > 29.5)
                                ))) or (#s784 > 3.5)
                          ) or (#s288 > 1.0)
                          and ((#s935 <= 2.5)
                            and ((#s1208 <= 0.5)
                              and ((#s1113 > 0.5)
                                and ((#s1491 > 2.0)
                                  and ((#s1493 <= 0.5)
                                    and ((#s277 > 0.5)
                                    )))) or (#s1208 > 0.5)
                              and ((#s81 <= 1.0)
                              )))) or (#s1370 > 1.0)
                      ) or (#s1369 > 0.5)
                      and ((#s128 <= 2.5)
                        and ((#s1504 <= 1.0)
                          and ((#s847 <= 1.0)
                            and ((#s89 <= 1.0)
                              and ((#s919 <= 6.5)
                                or (#s919 > 6.5)
                                and ((#s87 <= 0.5)
                                  and ((filesize <= 10092017.0)
                                  ) or (#s87 > 0.5)
                                ))))) or (#s128 > 2.5)
                        and ((#s1517 <= 1.0)
                          and ((#s1518 <= 12.0)
                            and ((#s1519 <= 1.5)
                              or (#s1519 > 1.5)
                              and ((filesize > 25131176.0)
                              ))) or (#s1517 > 1.0)
                          and ((#s766 > 1.5)
                            and ((#s106 > 1.0)
                              and ((#s1529 <= 1.0)
                                and ((#s1530 <= 1.5)
                                  and ((#s1531 <= 1.0)
                                    or (#s1531 > 1.0)
                                    and ((#s72 <= 2.0)
                                      and ((#s1143 <= 2.5)
                                        and ((#s622 <= 0.5)
                                          and ((filesize <= 19809960.0)
                                          )) or (#s1143 > 2.5)
                                      ) or (#s72 > 2.0)
                                      and ((filesize <= 11258992.0)
                                        or (filesize > 11258992.0)
                                        and ((#s622 <= 0.5)
                                        )))) or (#s1530 > 1.5)
                                  and ((#s1546 <= 3.0)
                                    and ((#s929 <= 3.0)
                                      or (#s929 > 3.0)
                                      and ((filesize <= 17175080.0)
                                      )) or (#s1546 > 3.0)
                                    and ((filesize <= 23943144.0)
                                      or (filesize > 23943144.0)
                                      and ((#s1143 > 2.5)
                                      )))) or (#s1529 > 1.0)
                                and ((#s1557 <= 3.0)
                                  and ((filesize <= 16839752.0)
                                    or (filesize > 16839752.0)
                                    and ((#s1560 <= 0.5)
                                    )) or (#s1557 > 3.0)
                                  and ((#s53 > 9.5)
                                    and ((filesize <= 36669096.0)
                                    ))))))))) or (#s1368 > 0.5)
                  ) or (#s95 > 0.5)
                  and ((#s919 <= 16.5)
                    and ((#s1570 <= 0.5)
                      and ((#s80 <= 0.5)
                        and ((#s71 <= 1.0)
                          and ((#s1460 <= 0.5)
                            or (#s1460 > 0.5)
                            and ((#s246 <= 0.5)
                            ))))) or (#s919 > 16.5)
                    and ((#s1581 > 2.0)
                      and ((#s1583 <= 1.0)
                      )))) or (#s1366 > 0.5)
                and ((#s1531 <= 4.5)
                  and ((#s1587 <= 2.5)
                    and ((#s1266 > 0.5)
                    ) or (#s1587 > 2.5)
                    and ((#s896 <= 1.0)
                      and ((#s861 > 1.5)
                      ))) or (#s1531 > 4.5)
                  and ((#s1143 <= 1.0)
                  )))) or (#s3 > 1.0)
          ) or (#s2 > 0.5)
          and ((#s460 <= 1.0)
            and ((#s53 <= 1.5)
            ) or (#s460 > 1.0)
          )) or (#s1 > 1.5)
        and ((#s100 <= 3.5)
          and ((#s121 <= 0.5)
            and ((#s1587 <= 0.5)
              and ((#s1608 <= 2.5)
                and ((#s594 <= 0.5)
                  and ((#s1610 <= 1.0)
                    and ((#s1611 <= 0.5)
                      and ((#s1439 <= 0.5)
                        and ((#s1613 <= 1.5)
                          and ((#s465 <= 0.5)
                            and ((#s535 > 0.5)
                              and ((#s1617 <= 1.0)
                                and ((#s1618 <= 1.0)
                                  and ((#s119 <= 0.5)
                                    and ((#s1620 <= 0.5)
                                      and ((#s586 <= 1.0)
                                        and ((#s836 <= 1.0)
                                          and ((#s558 <= 0.5)
                                            and ((#s590 > 0.5)
                                              and ((#s1626 <= 0.5)
                                                and ((#s73 <= 1.0)
                                                  and ((#s277 <= 0.5)
                                                    and ((#s154 <= 1.0)
                                                      and ((#s67 <= 1.0)
                                                        and ((filesize <= 77064.0)
                                                        )))) or (#s73 > 1.0)
                                                  and ((#s105 <= 1.0)
                                                    and ((#s1638 <= 19.5)
                                                      and ((#s67 > 1.0)
                                                        and ((#s83 <= 2.0)
                                                          and ((#s847 <= 1.0)
                                                            and ((#s1643 <= 0.5)
                                                              and ((#s969 > 1.0)
                                                                and ((#s622 > 0.5)
                                                                ))))))))) or (#s1626 > 0.5)
                                              )) or (#s558 > 0.5)
                                            and ((#s1655 > 1.0)
                                              and ((#s877 <= 0.5)
                                                and ((#s1658 <= 0.5)
                                                  and ((#s1214 <= 1.0)
                                                    and ((#s52 > 0.5)
                                                      and ((#s61 <= 0.5)
                                                      )))) or (#s877 > 0.5)
                                                and ((#s120 > 1.0)
                                                ))))) or (#s586 > 1.0)
                                        and ((#s56 <= 0.5)
                                          and ((#s959 <= 3.0)
                                            and ((#s90 > 0.5)
                                            ) or (#s959 > 3.0)
                                          ))) or (#s1620 > 0.5)
                                      and ((#s1678 > 1.0)
                                      )) or (#s119 > 0.5)
                                    and ((#s1091 <= 0.5)
                                      and ((#s1389 <= 0.5)
                                        and ((#s1683 <= 0.5)
                                          and ((#s1684 <= 3.0)
                                            and ((#s77 <= 61.5)
                                              and ((#s969 <= 1.0)
                                                and ((#s53 <= 0.5)
                                                  and ((#s959 > 3.0)
                                                  ))) or (#s77 > 61.5)
                                            )) or (#s1683 > 0.5)
                                        ) or (#s1389 > 0.5)
                                        and ((#s100 > 1.5)
                                          and ((#s116 <= 1.0)
                                            and ((#s52 > 0.5)
                                            ) or (#s116 > 1.0)
                                          ))) or (#s1091 > 0.5)
                                      and ((#s1703 <= 3.0)
                                      ))) or (#s1618 > 1.0)
                                ) or (#s1617 > 1.0)
                                and ((#s847 <= 1.0)
                                  and ((#s1007 > 2.0)
                                    and ((#s919 > 74.5)
                                    )) or (#s847 > 1.0)
                                ))) or (#s465 > 0.5)
                            and ((#s1714 <= 1.0)
                              and ((#s105 <= 0.5)
                                and ((#s723 <= 1.0)
                                  and ((#s1295 <= 0.5)
                                    and ((#s881 > 0.5)
                                    )) or (#s723 > 1.0)
                                ) or (#s105 > 0.5)
                                and ((#s1389 > 0.5)
                                  and ((#s152 <= 1.0)
                                    and ((#s1074 <= 0.5)
                                      and ((#s1727 <= 0.5)
                                        and ((#s819 > 0.5)
                                          and ((#s962 <= 0.5)
                                            and ((#s1731 <= 0.5)
                                              and ((#s65 > 1.0)
                                                and ((#s1620 <= 0.5)
                                                  and ((#s1735 > 0.5)
                                                  ))))))))))) or (#s1714 > 1.0)
                              and ((#s91 <= 1.0)
                                and ((#s1745 <= 1.5)
                                ) or (#s91 > 1.0)
                                and ((#s1748 > 1.0)
                                )))) or (#s1613 > 1.5)
                        ) or (#s1439 > 0.5)
                        and ((#s119 <= 1.5)
                          and ((#s1753 <= 4.0)
                            and ((#s54 > 2.0)
                            ) or (#s1753 > 4.0)
                          ) or (#s119 > 1.5)
                          and ((#s58 <= 0.5)
                          ))) or (#s1611 > 0.5)
                      and ((#s1761 <= 0.5)
                        and ((#s44 <= 0.5)
                          and ((#s295 <= 1.0)
                            and ((#s959 > 3.0)
                              and ((#s61 <= 0.5)
                                and ((filesize <= 70928.0)
                                  or (filesize > 70928.0)
                                  and ((#s1620 <= 0.5)
                                    and ((#s1770 > 0.5)
                                    ))) or (#s61 > 0.5)
                                and ((#s1774 <= 0.5)
                                  and ((#s87 <= 2.0)
                                    and ((#s1776 <= 1.0)
                                      and ((#s98 <= 0.5)
                                      )) or (#s87 > 2.0)
                                    and ((#s766 <= 0.5)
                                      and ((#s908 <= 1.0)
                                        and ((#s923 <= 0.5)
                                          and ((#s1784 <= 3.0)
                                            and ((filesize <= 74696.0)
                                            ) or (#s1784 > 3.0)
                                          ) or (#s923 > 0.5)
                                        )) or (#s766 > 0.5)
                                      and ((#s1437 > 0.5)
                                      ))))))) or (#s44 > 0.5)
                          and ((#s1796 <= 0.5)
                            and ((#s259 > 1.5)
                              and ((#s888 <= 0.5)
                                and ((#s1800 <= 0.5)
                                  and ((#s1295 <= 0.5)
                                    and ((#s1189 <= 1.0)
                                      and ((#s52 <= 0.5)
                                      ) or (#s1189 > 1.0)
                                    ) or (#s1295 > 0.5)
                                  ) or (#s1800 > 0.5)
                                ) or (#s888 > 0.5)
                              )) or (#s1796 > 0.5)
                            and ((#s1438 <= 3.5)
                              and ((#s1811 <= 0.5)
                                and ((#s247 <= 3.0)
                                ) or (#s1811 > 0.5)
                              )))) or (#s1761 > 0.5)
                        and ((#s1817 <= 1.5)
                          or (#s1817 > 1.5)
                          and ((#s995 <= 2.0)
                          )))) or (#s1610 > 1.0)
                  ) or (#s594 > 0.5)
                  and ((#s1823 <= 3.0)
                    and ((#s535 <= 2.0)
                    ))) or (#s1608 > 2.5)
                and ((#s1828 <= 5.0)
                  and ((#s1295 <= 1.0)
                    and ((#s899 > 5.0)
                      and ((#s1832 <= 1.0)
                        and ((#s1382 <= 2.0)
                          and ((#s558 <= 1.0)
                            and ((#s455 <= 1.5)
                              and ((#s151 <= 1.0)
                                and ((#s61 > 1.0)
                                  and ((filesize <= 232856.0)
                                  ))))))))))) or (#s1587 > 0.5)
              and ((#s1714 > 1.0)
                and ((#s1851 <= 0.5)
                )))))) or (#s0 > 1.5)
      and ((#s1856 <= 0.5)
        and ((#s1389 <= 0.5)
          and ((#s86 > 0.5)
          ))))
}