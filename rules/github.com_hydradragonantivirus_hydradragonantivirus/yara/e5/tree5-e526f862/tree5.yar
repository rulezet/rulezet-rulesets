rule tree5 {
  strings:
    $s0    = "operatingSystemVersionString" fullword
    $s1    = "getRequiredClass" fullword
    $s2    = "ZGVZN5boost10filesystem6detail8dot" fullword
    $s3    = "G16ComparisonResultOtF" fullword
    $s4    = "isAppStoreDistribution" fullword
    $s5    = "ZNSt6vectorI4CInvSaIS0" fullword
    $s6    = "supportsUIRestoring" fullword
    $s7    = "1onCopyLabelAction" fullword
    $s8    = "performActionForShortcutItem" fullword
    $s9    = "getblocktemplate" fullword
    $s10   = "IORegistryEntryFromPath" fullword
    $s11   = "navigationBarNodeSortingOrder" fullword
    $s12   = "AECreateAppleEvent" fullword
    $s13   = "applicationDockMenu" fullword
    $s14   = "executeWithPrivileges" fullword
    $s15   = "arrayWithJSONStringIgnoringNulls" fullword
    $s16   = "errcallEPPFvPK5DbEnvPKcS4" fullword
    $s17   = "KGWindowsController" fullword
    $s18   = "DUHAWAVAUATSPIII" fullword
    $s19   = "140213191008Z0A1" fullword
    $s20   = "kZBVTInstallerDownloadPathKey" fullword
    $s21   = "threadSafeMainBundle" fullword
    $s22   = "lastCrcListValuesCount" fullword
    $s23   = "linenoiseEditMoveHome" fullword
    $s24   = "krAttachHTTPForm" fullword
    $s25   = "UHAWAVAUATSHxLMMIHHExHhHEhHpHEpHxHE" fullword
    $s26   = "setButton1Action" fullword
    $s27   = "12CrtAllocatorELj0EE12PrettyPrefixENS" fullword
    $s28   = "140129192647Z0A1" fullword
    $s29   = "EqualizationPhase2" fullword
    $s30   = "UHAWAVAUATSH8LMHMHUHuHH" fullword
    $s31   = "UserNotifications" fullword
    $s32   = "handleHomeButtonSinglePressUp" fullword
    $s33   = "debugDescription" fullword
    $s34   = "ZTSN5boost18thread" fullword
    $s35   = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s37   = "kCFAllocatorDefault" fullword
    $s38   = "kSMDomainSystemLaunchd" fullword
    $s39   = "DEDEDEDEDEDEDEDE9E" fullword
    $s40   = "launchJavaApplication" fullword
    $s41   = "makeNewConnection" fullword
    $s42   = "CFBundleShortVersionString" fullword
    $s43   = "MobileCoreServices" fullword
    $s44   = "ddddddddddddddddddddddddddddddddsd" fullword
    $s45   = "DefaultRuneLocale" fullword
    $s46   = "191127221001Z0A1" fullword
    $s47   = "ApplicationServices" fullword
    $s48   = "getMethodDescription" fullword
    $s49   = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s50   = "initWithIdentifier" fullword
    $s51   = "gSearchProviderUrl" fullword
    $s52   = "retainAutoreleasedReturnValue" fullword
    $s53   = "setWorkspaceSessionActive" fullword
    $s54   = "b77a5c561934e089" fullword
    $s55   = "TpEQULved3Ly7GqqbjLfo6hqMSo" fullword
    $s56   = "CFArrayGetValueAtIndex" fullword
    $s57   = "UHAWAVAUATSPAAII" fullword
    $s58   = "SafariExtensionViewController" fullword
    $s59   = "HEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEHEgqV" fullword
    $s60   = "bundleIdentifier" fullword
    $s61   = "180123004003Z0A1" fullword
    $s62   = "PrivateFrameworks" fullword
    $s63   = "NSAddressOfSymbol" fullword
    $s64   = "HEHEHEHEHEHEHEHEHEHEHEHEHELuI" fullword
    $s65   = "dataWithContentsOfFile" fullword
    $s66   = "libswiftDispatch" fullword
    $s67   = "NSNotificationCenter" fullword
    $s69   = "CFConstantStringClassReference" fullword
    $s70   = "localizedStringForKey" fullword
    $s71   = "HEHEHEHEHEHEHEHEHEHEHE" fullword
    $s72   = "200219223002Z0B1" fullword
    $s73   = "caseInsensitiveCompare" fullword
    $s74   = "CFReadStreamCreateWithFile" fullword
    $s75   = "HMHMHMHMHMHMHMHMH" fullword
    $s76   = "9allocatorIcEEEC1ERKS5" fullword
    $s77   = "certificationauthority" fullword
    $s78   = "ZTSN5boost9exceptionE" fullword
    $s79   = "getInitializedObjCClass" fullword
    $s80   = "sqhIJsyyeFaPcYe7" fullword
    $s81   = "ZN9QListData7disposeEPNS" fullword
    $s82   = "FromStringAndSize" fullword
    $s83   = "stringWithFormat" fullword
    $s85   = "replaceObjectAtIndex" fullword
    $s86   = "UHAWAVAUATSPIIID" fullword
    $s87   = "certificateauthority0" fullword
    $s88   = "iPhoneSimulator10" fullword
    $s90   = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s91   = "isAccessibilityElement" fullword
    $s92   = "respondsToSelector" fullword
    $s94   = "ZN9QListData11shared" fullword
    $s95   = "lswiftObjectiveC" fullword
    $s96   = "autoreleaseReturnValue" fullword
    $s97   = "IOIteratorIsValid" fullword
    $s98   = "fileExistsAtPath" fullword
    $s99   = "dataUsingEncoding" fullword
    $s100  = "copyElephantBrain" fullword
    $s103  = "NSConcreteGlobalBlock" fullword
    $s104  = "NSStringFromClass" fullword
    $s105  = "NSDistributedNotificationCenter" fullword
    $s106  = "arrayWithObjects" fullword
    $s107  = "NSAutoreleasePool" fullword
    $s110  = "logKextUserClient" fullword
    $s111  = "CFStringCreateWithCString" fullword
    $s112  = "libswiftCoreFoundation" fullword
    $s113  = "ServiceManagement" fullword
    $s114  = "OSAtomicDecrement32" fullword
    $s115  = "350209214036Z0b1" fullword
    $s116  = "UHAWAVAUATSPIHIH" fullword
    $s117  = "SystemConfiguration" fullword
    $s118  = "intrinsicContentSize" fullword
    $s119  = "abcdefghijklmnopqrstuvwxyz" fullword
    $s120  = "CFBundleIdentifier" fullword
    $s121  = "UHAWAVAUATSH8IIH" fullword
    $s122  = "9allocatorIcEEEE" fullword
    $s147  = "270201221215Z0y1" fullword
    $s179  = "UHAWAVAUATSHHHuE" fullword
    $s180  = "autoreleasePoolPop" fullword
    $s181  = "IOCreatePlugInInterfaceForService" fullword
    $s182  = "allocBatchP11objc" fullword
    $s184  = "JSObjectSetProperty" fullword
    $s187  = "CFStringGetCString" fullword
    $s193  = "UHAWAVAUATSH8IHH" fullword
    $s194  = "HEHEHEHEHEHEHEHEHEHEHEHEI" fullword
    $s197  = "ImageCaptureCore" fullword
    $s198  = "enumerationMutation" fullword
    $s203  = "SecItemCopyMatching" fullword
    $s205  = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s207  = "0123456789abcdef" fullword
    $s213  = "DisableThreadLibraryCalls" fullword
    $s214  = "createFileAtPath" fullword
    $s216  = "ecpointformatlist" fullword
    $s218  = "category23default" fullword
    $s219  = "certificateauthority" fullword
    $s221  = "UIViewController" fullword
    $s223  = "traitsIcEEE3putEc" fullword
    $s281  = "CFURLGetFileSystemRepresentation" fullword
    $s286  = "AuthorizationFree" fullword
    $s341  = "numberWithUnsignedInteger" fullword
    $s342  = "stringWithString" fullword
    $s344  = "210412223435Z0V1" fullword
    $s346  = "stringByAppendingPathComponent" fullword
    $s347  = "CFBundleExecutable" fullword
    $s350  = "numberWithDouble" fullword
    $s351  = "NSAssertionHandler" fullword
    $s368  = "replaceCharactersInRange" fullword
    $s373  = "efCkKaADK3CAKRCNC" fullword
    $s375  = "ShCsSwSzfKpADKfADCNK" fullword
    $s384  = "191128154500Z0A1" fullword
    $s385  = "20191001103003Z0" fullword
    $s389  = "ZN7QLayout18setContentsMarginsEiiii" fullword
    $s399  = "UHAWAVAUATSHHMIIM" fullword
    $s425  = "NSPropertyListSerialization" fullword
    $s429  = "substringToIndex" fullword
    $s454  = "NSMutableURLRequest" fullword
    $s455  = "TZFE10FoundationSS36" fullword
    $s456  = "objectAtIndexedSubscript" fullword
    $s463  = "DispatchOnceCounter" fullword
    $s478  = "stringWithUTF8String" fullword
    $s488  = "20191105000000Z0" fullword
    $s495  = "getInstanceMethod" fullword
    $s502  = "UHAWAVAUATSPIIHt" fullword
    $s536  = "CFBundleInfoDictionaryVersion" fullword
    $s537  = "ZBNetworkReachability" fullword
    $s543  = "CFBundleCopyResourceURL" fullword
    $s554  = "ZN2cv10AutoBufferIhLm4104EE8allocateEm" fullword
    $s555  = "ZBUSystemInformation" fullword
    $s556  = "calcDecodeLength" fullword
    $s557  = "columnIndexForName" fullword
    $s558  = "numberWithUnsignedLong" fullword
    $s559  = "bQHbQHbQHbQHbqHbHbQHbHbQHbQHb" fullword
    $s560  = "numberWithUnsignedInt" fullword
    $s561  = "completionHandler" fullword
    $s563  = "kZBSizeStringKey" fullword
    $s565  = "CFDictionaryCreateMutable" fullword
    $s566  = "scheduledTimerWithTimeInterval" fullword
    $s567  = "countByEnumeratingWithState" fullword
    $s570  = "setAllowedFileTypes" fullword
    $s571  = "adjustsLetterSpacingToFitWidth" fullword
    $s572  = "convertObjCBoolToBoolFVS" fullword
    $s575  = "retainAutorelease" fullword
    $s576  = "CSo12NSDictionary" fullword
    $s582  = "loadWeakRetained" fullword
    $s589  = "CFStringMakeConstantString" fullword
    $s592  = "UHAWAVAUATSH8IIHH" fullword
    $s599  = "sharedApplication" fullword
    $s602  = "IOConnectMapMemory" fullword
    $s603  = "CreateDeviceAsyncEventSource" fullword
    $s610  = "getExistentialTypeMetadata" fullword
    $s617  = "alSourceQueueBuffers" fullword
    $s658  = "ZN16QLoggingCategoryD1Ev" fullword
    $s693  = "ellipticcurvelist" fullword
    $s696  = "UIGestureRecognizer" fullword
    $s697  = "9allocatorIcEEE6insertEmPKcm" fullword
    $s698  = "SleepNotificationMBS" fullword
    $s699  = "traitsIcEEE5tellgEv" fullword
    $s703  = "ddddduhhhhhhhhhh" fullword
    $s704  = "didFinishDownloadingToURL" fullword
    $s709  = "GenerateConnectionID" fullword
    $s712  = "k7kBkQkpkkkkkkkkkkflmllllll" fullword
    $s717  = "mediumspringgreen" fullword
    $s721  = "nodeIPN7netflix4base6ThreadEEEC2ERKS5" fullword
    $s722  = "GetDiskFreeSpace" fullword
    $s723  = "E6targetERKSt9type" fullword
    $s728  = "crossCertificatePair" fullword
    $s742  = "StringCharCodeAt" fullword
    $s743  = "terminationStatus" fullword
    $s799  = "CGContextFillPath" fullword
    $s824  = "CFURLCopyFileSystemPath" fullword
    $s831  = "IOPlatformExpertDevice" fullword
    $s846  = "N5boost9exceptionE" fullword
    $s878  = "IOServiceGetMatchingServices" fullword
    $s892  = "registerClassPair" fullword
    $s899  = "USBInterfaceOpen" fullword
    $s908  = "fUHAWAVSPIHIIv0Ht" fullword
    $s912  = "contentsOfDirectoryAtPath" fullword
    $s915  = "CommitTransaction" fullword
    $s919  = "CGContextRelease" fullword
    $s953  = "setCanChooseDirectories" fullword
    $s959  = "140305162647Z0A1" fullword
    $s964  = "objectForKeyedSubscript" fullword
    $s965  = "lengthOfBytesUsingEncoding" fullword
    $s967  = "initWithFireDate" fullword
    $s976  = "timeIntervalSinceDate" fullword
    $s979  = "shouldDragDocumentWithEvent" fullword
    $s984  = "arrayWithCapacity" fullword
    $s985  = "conformsToProtocol" fullword
    $s1030 = "N5boost6detail11thread" fullword
    $s1033 = "N5boost9gregorian15bad" fullword
    $s1040 = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s1043 = "ZNK5boost3any6holderImE4typeEv" fullword
    $s1049 = "22BufferedTransformationENS" fullword
    $s1062 = "setWebViewController" fullword
    $s1063 = "runningApplicationWithProcessIdentifier" fullword
    $s1064 = "dataWithJSONObject" fullword
    $s1069 = "connectionDidFinishLoading" fullword
    $s1074 = "setStandardOutput" fullword
    $s1082 = "defaultSessionConfiguration" fullword
    $s1089 = "setHTTPShouldHandleCookies" fullword
    $s1100 = "ponponqqtsrtsruuxwvwvyy" fullword
    $s1109 = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s1112 = "N4laya11JSCFunctionIPFvllEEE" fullword
    $s1114 = "libswiftCoreGraphics" fullword
    $s1115 = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s1119 = "NetworkExtension" fullword
    $s1153 = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s1187 = "backingScaleFactor" fullword
    $s1188 = "includingPropertiesForKeys" fullword
    $s1192 = "NSUndoManagerProxy" fullword
    $s1194 = "didFailToContinueUserActivityWithType" fullword
    $s1203 = "NSRunningApplication" fullword
    $s1219 = "collectingEnabled" fullword
    $s1224 = "setUrlAfterUpdate" fullword
    $s1235 = "IORegistryEntryCreateCFProperty" fullword
    $s1241 = "unretainedObject" fullword
    $s1244 = "cancelAllOperations" fullword
    $s1245 = "enumerateKeysAndObjectsUsingBlock" fullword
    $s1246 = "componentsSeparatedByString" fullword
    $s1250 = "CLSURLSessionConfiguration" fullword
    $s1253 = "componentsSeparatedByCharactersInSet" fullword
    $s1255 = "UHAWAVAUATSH8HIH" fullword
    $s1258 = "NSAppleEventManager" fullword
    $s1262 = "CFNumberGetValue" fullword
    $s1275 = "applicationWillUnhide" fullword
    $s1284 = "MonoContinuation" fullword
    $s1285 = "setLargeTitleTextAttributes" fullword
    $s1287 = "didEndDisplayingHeaderView" fullword
    $s1288 = "timerWithTimeInterval" fullword
    $s1289 = "shouldSaveApplicationState" fullword
    $s1291 = "dictionaryWithContentsOfFile" fullword
    $s1310 = "didDismissWithButtonIndex" fullword
    $s1317 = "handleEventsForBackgroundURLSession" fullword
    $s1325 = "34CachingTransactionSignatureChecker" fullword
    $s1326 = "EEEEEEEEE7disposeEv" fullword
    $s1328 = "ZNK5boost9gregorian4date11day" fullword
    $s1336 = "UIApplicationDelegate" fullword
    $s1338 = "IntermediateBuildFilesPath" fullword
    $s1341 = "applicationWillHide" fullword
    $s1354 = "NSStringPboardType" fullword
    $s1356 = "ZN5tools6base586encodeERKNSt3" fullword
    $s1357 = "18numpunctIcE12do" fullword
    $s1364 = "NSAccessibilityValueChangedNotification" fullword
    $s1367 = "kSecAttrProtocolFTP" fullword
    $s1368 = "kMDItemWhereFroms" fullword
    $s1370 = "willDismissWithButtonIndex" fullword
    $s1371 = "NSMutableOrderedSet" fullword
    $s1373 = "redirectResponse" fullword
    $s1374 = "HYHyHVHVHVHvHMHHMH9uIu" fullword
    $s1375 = "ATEContentBlockersRulesWereSet" fullword
    $s1376 = "JSValueMakeUndefined" fullword
    $s1377 = "NSDistantObjectRequest" fullword
    $s1380 = "copyClassNamesForImage" fullword
    $s1382 = "tempExtensionsDict" fullword
    $s1383 = "traitsIwEEE5writeEPKwl" fullword
    $s1391 = "forKeyedSubscriptP19NSMutableDictionaryP13objc" fullword
    $s1394 = "fastIndexForKnownKey" fullword
    $s1398 = "selectorPFP11objc" fullword
    $s1411 = "resignFirstResponder" fullword
    $s1412 = "ZL22copySwiftV1MangledNamePKcb" fullword
    $s1415 = "objectForKeyP11objc" fullword
    $s1418 = "convertBoolToObjCBoolyAA0eF0VSbF" fullword
    $s1421 = "getTupleTypeMetadata2" fullword
    $s1433 = "ZL30NSUndoManagerProxy" fullword
    $s1441 = "CFBundleGetVersionNumber" fullword
    $s1442 = "SCNetworkReachabilityUnscheduleFromRunLoop" fullword
    $s1443 = "autoreleasePoolPushv" fullword
    $s1445 = "enumerateObjectsUsingBlock" fullword
    $s1446 = "addEntriesFromDictionaryP11objc" fullword
    $s1450 = "setInstanceVariableP11objc" fullword
    $s1468 = "RGp0SARARARARARA" fullword
    $s1474 = "stift2mront3flahu" fullword
    $s1487 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1499 = "didRegisterForRemoteNotificationsWithDeviceToken" fullword
    $s1507 = "willResizeForVersionBrowserWithMaxPreferredSize" fullword
    $s1508 = "welcomeScreenIdentifier" fullword
    $s1510 = "applicationShouldOpenUntitledFile" fullword
    $s1511 = "retainAutoreleaseReturnValue" fullword
    $s1521 = "ZTSN5Audio6DeviceE" fullword
    $s1525 = "NSFilenamesPboardType" fullword
    $s1534 = "initWithContentsOfURL" fullword
    $s1535 = "ZL20fixStringForCoreDataP11objc" fullword
    $s1537 = "componentsJoinedByString" fullword
    $s1540 = "deletedMethodError" fullword
    $s1547 = "onCancelAllButton" fullword
    $s1556 = "setStandardInput" fullword
    $s1563 = "kMKNotificationActionReviewActionIdentifier" fullword
    $s1582 = "ZL16scanMangledFieldRPKcS0" fullword
    $s1584 = "applicationShouldHandleReopen" fullword
    $s1586 = "fileHandleForReading" fullword
    $s1587 = "ARCLiteIndexedSubscripting" fullword
    $s1597 = "applicationDidResignActive" fullword
    $s1611 = "didUpdateUserActivity" fullword
    $s1612 = "UHAWAVAUATSHHIH5M" fullword
    $s1630 = "delegateHandlesKey" fullword
    $s1632 = "RARARARARARARARARARAZAp" fullword
    $s1639 = "SSS10FoundationE19" fullword
    $s1641 = "kSecMatchLimitAll" fullword
    $s1649 = "showNotification" fullword
    $s1652 = "EXUa2Kc9Qd9ysfHNqqIFg" fullword
    $s1656 = "Dfllononqpqpsrr2" fullword
    $s1664 = "responseSerializer" fullword
    $s1694 = "updatedStatusTitle" fullword
    $s1701 = "downloadTaskWithResumeData" fullword
    $s1702 = "ZL19transcribeProtocolsP10objc" fullword
    $s1716 = "objectAtIndexedSubscriptP7NSArrayP13objc" fullword
    $s1725 = "UHAWAVSPHIIHtHKt6" fullword
    $s1729 = "setTitleBarEndColor" fullword
    $s1734 = "ZBInstallationInfo" fullword
    $s1735 = "MacKeeperPrivilegedHelper" fullword
    $s1736 = "characterIsMember" fullword
    $s1754 = "withIntermediateDirectories" fullword
    $s1766 = "dataTaskWithRequest" fullword
    $s1779 = "runningApplications" fullword
    $s1790 = "assertionFailure" fullword
    $s1798 = "setAttributedTitle" fullword
    $s1806 = "NSJSONSerialization" fullword

  condition:
    ((#s0 <= 0.5)
      and ((#s1 <= 3.5)
        and ((#s2 <= 0.5)
          and ((#s3 <= 1.5)
            and ((#s4 <= 0.5)
              and ((#s5 <= 2.0)
                and ((#s6 <= 0.5)
                  and ((#s7 <= 0.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 0.5)
                        and ((#s10 <= 1.5)
                          and ((#s11 <= 0.5)
                            and ((#s12 <= 2.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 1.0)
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
                                                              and ((#s29 <= 0.5)
                                                                and ((#s30 <= 0.5)
                                                                  and ((#s31 <= 1.5)
                                                                    and ((#s32 <= 0.5)
                                                                      and ((#s33 <= 1.5)
                                                                        and ((#s34 <= 1.5)
                                                                          and ((#s35 <= 0.5)
                                                                            and ((filesize <= 70166.0)
                                                                              and ((#s37 <= 1.5)
                                                                                and ((#s38 <= 1.0)
                                                                                  and ((#s39 <= 0.5)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 0.5)
                                                                                              and ((#s45 <= 0.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 1.5)
                                                                                                    and ((#s48 <= 1.5)
                                                                                                      and ((#s49 <= 0.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 1.0)
                                                                                                            and ((#s52 <= 0.5)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((#s54 <= 0.5)
                                                                                                                  and ((#s55 <= 0.5)
                                                                                                                    and ((#s56 <= 0.5)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 0.5)
                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                    and ((#s64 <= 0.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s66 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((filesize <= 50006.0)
                                                                                                                                              and ((#s69 <= 1.5)
                                                                                                                                                and ((#s70 <= 0.5)
                                                                                                                                                  and ((#s71 <= 0.5)
                                                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                                                      and ((#s73 <= 0.5)
                                                                                                                                                        and ((#s74 <= 0.5)
                                                                                                                                                          and ((#s75 <= 0.5)
                                                                                                                                                            and ((#s76 <= 1.5)
                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                and ((#s78 <= 0.5)
                                                                                                                                                                  and ((#s79 <= 0.5)
                                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                                      and ((#s81 <= 0.5)
                                                                                                                                                                        and ((#s82 <= 0.5)
                                                                                                                                                                          and ((#s83 <= 0.5)
                                                                                                                                                                            and ((#s37 <= 0.5)
                                                                                                                                                                              and ((#s85 <= 0.5)
                                                                                                                                                                                and ((#s86 <= 0.5)
                                                                                                                                                                                  and ((#s87 <= 0.5)
                                                                                                                                                                                    and ((#s88 <= 1.0)
                                                                                                                                                                                      and ((filesize <= 19648.0)
                                                                                                                                                                                        and ((#s90 <= 0.5)
                                                                                                                                                                                          and ((#s91 <= 0.5)
                                                                                                                                                                                            and ((#s92 <= 0.5)
                                                                                                                                                                                              and ((#s76 <= 0.5)
                                                                                                                                                                                                and ((#s94 <= 0.5)
                                                                                                                                                                                                  and ((#s95 <= 0.5)
                                                                                                                                                                                                    and ((#s96 <= 0.5)
                                                                                                                                                                                                      and ((#s97 <= 1.0)
                                                                                                                                                                                                        and ((#s98 <= 0.5)
                                                                                                                                                                                                          and ((#s99 <= 0.5)
                                                                                                                                                                                                            and ((#s100 <= 1.5)
                                                                                                                                                                                                              and ((filesize > 4222.0)
                                                                                                                                                                                                                and ((#s103 <= 0.5)
                                                                                                                                                                                                                  and ((#s104 <= 0.5)
                                                                                                                                                                                                                    and ((#s105 <= 1.0)
                                                                                                                                                                                                                      and ((#s106 <= 0.5)
                                                                                                                                                                                                                        and ((#s107 <= 1.0)
                                                                                                                                                                                                                          and ((filesize > 4236.0)
                                                                                                                                                                                                                            and ((#s110 <= 1.0)
                                                                                                                                                                                                                              and ((#s111 <= 0.5)
                                                                                                                                                                                                                                and ((#s112 <= 0.5)
                                                                                                                                                                                                                                  and ((#s113 <= 1.0)
                                                                                                                                                                                                                                    and ((#s114 <= 0.5)
                                                                                                                                                                                                                                      and ((#s115 <= 0.5)
                                                                                                                                                                                                                                        and ((#s116 <= 0.5)
                                                                                                                                                                                                                                          and ((#s117 <= 0.5)
                                                                                                                                                                                                                                            and ((#s118 <= 2.0)
                                                                                                                                                                                                                                              and ((#s119 <= 1.0)
                                                                                                                                                                                                                                                and ((#s120 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s121 <= 0.5)
                                                                                                                                                                                                                                                    and ((#s122 <= 1.0)
                                                                                                                                                                                                                                                      and ((filesize <= 5196.0)
                                                                                                                                                                                                                                                        and ((#s69 <= 0.5)
                                                                                                                                                                                                                                                          and ((filesize > 5154.0)
                                                                                                                                                                                                                                                          )) or (filesize > 5196.0)
                                                                                                                                                                                                                                                        and ((filesize <= 8988.0)
                                                                                                                                                                                                                                                          and ((#s69 <= 0.5)
                                                                                                                                                                                                                                                            and ((filesize > 8946.0)
                                                                                                                                                                                                                                                            )) or (filesize > 8988.0)
                                                                                                                                                                                                                                                          and ((filesize > 16444.0)
                                                                                                                                                                                                                                                            and ((filesize <= 16478.0)
                                                                                                                                                                                                                                                            ))))))))))) or (#s115 > 0.5)
                                                                                                                                                                                                                                        and ((#s147 > 0.5)
                                                                                                                                                                                                                                          and ((#s117 <= 1.0)
                                                                                                                                                                                                                                            and ((#s115 <= 1.5)
                                                                                                                                                                                                                                              and ((filesize > 14976.0)
                                                                                                                                                                                                                                                and ((filesize <= 16744.0)
                                                                                                                                                                                                                                                )))))))))) or (#s110 > 1.0)
                                                                                                                                                                                                                            )))))))) or (#s100 > 1.5)
                                                                                                                                                                                                            ))))))))))) or (filesize > 19648.0)
                                                                                                                                                                                        and ((#s179 <= 0.5)
                                                                                                                                                                                          and ((#s180 <= 1.5)
                                                                                                                                                                                            and ((#s181 <= 2.0)
                                                                                                                                                                                              and ((#s182 <= 0.5)
                                                                                                                                                                                                and ((#s113 <= 1.0)
                                                                                                                                                                                                  and ((#s184 <= 1.0)
                                                                                                                                                                                                    and ((#s147 <= 0.5)
                                                                                                                                                                                                      and ((#s98 <= 0.5)
                                                                                                                                                                                                        and ((#s187 <= 0.5)
                                                                                                                                                                                                          and ((#s119 <= 0.5)
                                                                                                                                                                                                            and ((#s100 <= 3.0)
                                                                                                                                                                                                              and ((#s103 <= 0.5)
                                                                                                                                                                                                                and ((#s96 <= 0.5)
                                                                                                                                                                                                                  and ((#s76 <= 0.5)
                                                                                                                                                                                                                    and ((#s193 <= 0.5)
                                                                                                                                                                                                                      and ((#s194 <= 0.5)
                                                                                                                                                                                                                        and ((filesize <= 19714.0)
                                                                                                                                                                                                                          or (filesize > 19714.0)
                                                                                                                                                                                                                          and ((#s197 <= 1.0)
                                                                                                                                                                                                                            and ((#s198 <= 0.5)
                                                                                                                                                                                                                              and ((filesize <= 20802.0)
                                                                                                                                                                                                                                and ((filesize > 20734.0)
                                                                                                                                                                                                                                ) or (filesize > 20802.0)
                                                                                                                                                                                                                                and ((#s203 <= 1.0)
                                                                                                                                                                                                                                  and ((#s114 <= 0.5)
                                                                                                                                                                                                                                    and ((#s205 <= 0.5)
                                                                                                                                                                                                                                      and ((#s90 <= 1.0)
                                                                                                                                                                                                                                        and ((#s207 <= 0.5)
                                                                                                                                                                                                                                          and ((#s95 <= 0.5)
                                                                                                                                                                                                                                            and ((#s111 <= 0.5)
                                                                                                                                                                                                                                              and ((#s47 <= 0.5)
                                                                                                                                                                                                                                                and ((#s117 <= 1.0)
                                                                                                                                                                                                                                                  and ((#s69 <= 0.5)
                                                                                                                                                                                                                                                    and ((#s213 <= 1.0)
                                                                                                                                                                                                                                                      and ((#s214 <= 0.5)
                                                                                                                                                                                                                                                        and ((#s121 <= 1.0)
                                                                                                                                                                                                                                                          and ((#s216 <= 1.0)
                                                                                                                                                                                                                                                            and ((#s116 <= 0.5)
                                                                                                                                                                                                                                                              and ((#s218 <= 3.0)
                                                                                                                                                                                                                                                                and ((#s219 <= 0.5)
                                                                                                                                                                                                                                                                  and ((#s99 <= 0.5)
                                                                                                                                                                                                                                                                    and ((#s221 <= 0.5)
                                                                                                                                                                                                                                                                      and ((#s115 <= 0.5)
                                                                                                                                                                                                                                                                        and ((#s223 <= 1.0)
                                                                                                                                                                                                                                                                          and ((filesize <= 25220.0)
                                                                                                                                                                                                                                                                            and ((filesize <= 25140.0)
                                                                                                                                                                                                                                                                              and ((filesize <= 25044.0)
                                                                                                                                                                                                                                                                                and ((filesize <= 21653.5)
                                                                                                                                                                                                                                                                                  and ((filesize > 21624.0)
                                                                                                                                                                                                                                                                                  )) or (filesize > 25044.0)
                                                                                                                                                                                                                                                                                and ((filesize <= 25116.0)
                                                                                                                                                                                                                                                                                )) or (filesize > 25140.0)
                                                                                                                                                                                                                                                                            ) or (filesize > 25220.0)
                                                                                                                                                                                                                                                                            and ((filesize <= 26140.0)
                                                                                                                                                                                                                                                                              and ((filesize > 26048.0)
                                                                                                                                                                                                                                                                              ) or (filesize > 26140.0)
                                                                                                                                                                                                                                                                              and ((filesize > 32996.0)
                                                                                                                                                                                                                                                                                and ((filesize <= 33044.0)
                                                                                                                                                                                                                                                                                  or (filesize > 33044.0)
                                                                                                                                                                                                                                                                                  and ((filesize <= 38360.0)
                                                                                                                                                                                                                                                                                    and ((filesize > 38276.0)
                                                                                                                                                                                                                                                                                    ))))))))))))))))))))))))))))))) or (#s194 > 0.5)
                                                                                                                                                                                                                      ))))) or (#s100 > 3.0)
                                                                                                                                                                                                            ) or (#s119 > 0.5)
                                                                                                                                                                                                          ))) or (#s147 > 0.5)
                                                                                                                                                                                                      and ((#s281 <= 1.0)
                                                                                                                                                                                                        and ((#s122 <= 17.0)
                                                                                                                                                                                                          and ((#s147 <= 1.5)
                                                                                                                                                                                                            and ((filesize <= 27304.0)
                                                                                                                                                                                                              and ((filesize <= 27176.0)
                                                                                                                                                                                                                and ((#s286 <= 0.5)
                                                                                                                                                                                                                  and ((#s115 > 1.5)
                                                                                                                                                                                                                    and ((filesize <= 24000.0)
                                                                                                                                                                                                                      and ((filesize > 23824.0)
                                                                                                                                                                                                                      )))) or (filesize > 27176.0)
                                                                                                                                                                                                              ) or (filesize > 27304.0)
                                                                                                                                                                                                              and ((#s286 <= 0.5)
                                                                                                                                                                                                                and ((filesize <= 28824.0)
                                                                                                                                                                                                                  and ((#s115 > 1.5)
                                                                                                                                                                                                                    and ((#s219 <= 0.5)
                                                                                                                                                                                                                      and ((#s117 <= 1.0)
                                                                                                                                                                                                                        and ((filesize > 28440.0)
                                                                                                                                                                                                                        )))))))))))))))) or (#s179 > 0.5)
                                                                                                                                                                                        )))))))))) or (#s80 > 0.5)
                                                                                                                                                                    )))) or (#s76 > 1.5)
                                                                                                                                                              and ((#s147 > 0.5)
                                                                                                                                                                and ((filesize > 38480.0)
                                                                                                                                                                ))) or (#s75 > 0.5)
                                                                                                                                                          )))) or (#s71 > 0.5)
                                                                                                                                                  )) or (#s69 > 1.5)
                                                                                                                                                and ((#s341 <= 0.5)
                                                                                                                                                  and ((#s342 <= 0.5)
                                                                                                                                                    and ((#s70 <= 0.5)
                                                                                                                                                      and ((#s344 <= 0.5)
                                                                                                                                                        and ((#s115 <= 0.5)
                                                                                                                                                          and ((#s346 <= 0.5)
                                                                                                                                                            and ((#s347 <= 0.5)
                                                                                                                                                              and ((#s105 <= 1.0)
                                                                                                                                                                and ((#s180 <= 1.0)
                                                                                                                                                                  and ((#s350 <= 0.5)
                                                                                                                                                                    and ((#s351 <= 1.0)
                                                                                                                                                                      and ((#s198 > 1.0)
                                                                                                                                                                      ))))))))))))) or (filesize > 50006.0)
                                                                                                                                              and ((#s351 <= 1.0)
                                                                                                                                                and ((#s117 <= 0.5)
                                                                                                                                                  and ((#s368 <= 0.5)
                                                                                                                                                    and ((#s94 <= 1.0)
                                                                                                                                                      and ((#s88 <= 1.0)
                                                                                                                                                        and ((#s107 <= 0.5)
                                                                                                                                                          and ((#s106 <= 0.5)
                                                                                                                                                            and ((#s373 <= 0.5)
                                                                                                                                                              and ((filesize <= 50212.0)
                                                                                                                                                                and ((#s375 <= 0.5)
                                                                                                                                                                  and ((#s90 <= 1.5)
                                                                                                                                                                    and ((filesize <= 50094.0)
                                                                                                                                                                      and ((#s205 <= 1.0)
                                                                                                                                                                      ) or (filesize > 50094.0)
                                                                                                                                                                    )) or (#s375 > 0.5)
                                                                                                                                                                ) or (filesize > 50212.0)
                                                                                                                                                                and ((#s384 <= 0.5)
                                                                                                                                                                  and ((#s385 <= 0.5)
                                                                                                                                                                    and ((#s92 <= 0.5)
                                                                                                                                                                      and ((#s69 <= 0.5)
                                                                                                                                                                        and ((#s121 <= 0.5)
                                                                                                                                                                          and ((#s389 <= 1.0)
                                                                                                                                                                            and ((#s223 <= 1.0)
                                                                                                                                                                              and ((#s115 > 1.5)
                                                                                                                                                                                and ((#s205 <= 1.0)
                                                                                                                                                                                  and ((#s82 <= 1.0)
                                                                                                                                                                                    and ((#s81 <= 1.0)
                                                                                                                                                                                      and ((#s87 <= 0.5)
                                                                                                                                                                                        and ((filesize > 68019.5)
                                                                                                                                                                                          and ((#s399 <= 0.5)
                                                                                                                                                                                            and ((#s219 > 0.5)
                                                                                                                                                                                            ))))))))))))) or (#s385 > 0.5)
                                                                                                                                                                  ) or (#s384 > 0.5)
                                                                                                                                                                )) or (#s373 > 0.5)
                                                                                                                                                            ))))))))) or (#s67 > 0.5)
                                                                                                                                            and ((#s67 > 1.5)
                                                                                                                                              and ((#s425 <= 1.0)
                                                                                                                                                and ((#s115 <= 1.5)
                                                                                                                                                  and ((#s70 <= 0.5)
                                                                                                                                                    and ((#s115 <= 0.5)
                                                                                                                                                      and ((#s429 > 0.5)
                                                                                                                                                        and ((#s92 > 0.5)
                                                                                                                                                        )))) or (#s115 > 1.5)
                                                                                                                                                  and ((#s198 <= 1.0)
                                                                                                                                                  ))))))) or (#s64 > 0.5)
                                                                                                                                    ))) or (#s61 > 0.5)
                                                                                                                              )) or (#s59 > 0.5)
                                                                                                                          ) or (#s58 > 0.5)
                                                                                                                        ))) or (#s55 > 0.5)
                                                                                                                  ) or (#s54 > 0.5)
                                                                                                                ) or (#s53 > 0.5)
                                                                                                              ) or (#s52 > 0.5)
                                                                                                              and ((#s454 <= 0.5)
                                                                                                                and ((#s455 <= 0.5)
                                                                                                                  and ((#s456 <= 0.5)
                                                                                                                    and ((#s58 <= 0.5)
                                                                                                                      and ((#s221 <= 0.5)
                                                                                                                        and ((#s115 > 1.5)
                                                                                                                          and ((#s425 <= 1.0)
                                                                                                                            and ((#s69 <= 3.0)
                                                                                                                              and ((#s463 <= 0.5)
                                                                                                                                and ((#s87 <= 0.5)
                                                                                                                                )))))) or (#s58 > 0.5)
                                                                                                                    ))))) or (#s51 > 1.0)
                                                                                                          )) or (#s49 > 0.5)
                                                                                                      ) or (#s48 > 1.5)
                                                                                                      and ((#s478 <= 0.5)
                                                                                                        and ((#s456 > 3.0)
                                                                                                          and ((#s70 <= 1.5)
                                                                                                          )))) or (#s47 > 1.5)
                                                                                                    and ((#s33 > 0.5)
                                                                                                    )) or (#s46 > 0.5)
                                                                                                  and ((#s488 <= 0.5)
                                                                                                    and ((filesize > 68504.0)
                                                                                                    ) or (#s488 > 0.5)
                                                                                                  )) or (#s45 > 0.5)
                                                                                                and ((#s47 <= 1.0)
                                                                                                  and ((#s37 <= 0.5)
                                                                                                    and ((#s495 <= 1.0)
                                                                                                      and ((#s77 <= 0.5)
                                                                                                        and ((#s478 <= 0.5)
                                                                                                          and ((#s187 <= 1.0)
                                                                                                            and ((#s87 <= 0.5)
                                                                                                              and ((#s69 <= 0.5)
                                                                                                                and ((#s219 <= 0.5)
                                                                                                                  and ((#s502 <= 0.5)
                                                                                                                    and ((#s115 <= 1.5)
                                                                                                                      and ((filesize > 38898.0)
                                                                                                                        and ((#s122 <= 1.0)
                                                                                                                          and ((filesize <= 40442.0)
                                                                                                                          ))) or (#s115 > 1.5)
                                                                                                                      and ((#s76 <= 1.0)
                                                                                                                        and ((#s82 <= 1.0)
                                                                                                                          and ((filesize <= 29928.0)
                                                                                                                          ))))))))))))))) or (#s44 > 0.5)
                                                                                            )) or (#s42 > 0.5)
                                                                                          and ((#s106 <= 0.5)
                                                                                            and ((#s37 > 0.5)
                                                                                              and ((#s47 > 1.0)
                                                                                              )) or (#s106 > 0.5)
                                                                                            and ((#s536 <= 0.5)
                                                                                              and ((#s537 > 0.5)
                                                                                              )))) or (#s41 > 0.5)
                                                                                      ) or (#s40 > 0.5)
                                                                                      and ((#s117 <= 1.0)
                                                                                        and ((#s543 <= 0.5)
                                                                                          and ((#s187 <= 0.5)
                                                                                            or (#s187 > 0.5)
                                                                                            and ((filesize <= 20408.0)
                                                                                            ))))) or (#s39 > 0.5)
                                                                                  ) or (#s38 > 1.0)
                                                                                )) or (filesize > 70166.0)
                                                                              and ((#s554 <= 2.0)
                                                                                and ((#s555 <= 1.0)
                                                                                  and ((#s556 <= 1.0)
                                                                                    and ((#s557 <= 2.0)
                                                                                      and ((#s558 <= 0.5)
                                                                                        and ((#s559 <= 1.5)
                                                                                          and ((#s560 <= 0.5)
                                                                                            and ((#s561 <= 0.5)
                                                                                              and ((#s115 <= 0.5)
                                                                                                and ((#s563 <= 0.5)
                                                                                                  and ((#s45 <= 0.5)
                                                                                                    and ((#s565 <= 0.5)
                                                                                                      and ((#s566 <= 0.5)
                                                                                                        and ((#s567 <= 0.5)
                                                                                                          and ((#s121 <= 0.5)
                                                                                                            and ((filesize <= 457316.0)
                                                                                                              and ((#s570 <= 0.5)
                                                                                                                and ((#s571 <= 0.5)
                                                                                                                  and ((#s572 <= 0.5)
                                                                                                                    and ((#s347 <= 0.5)
                                                                                                                      and ((#s198 <= 0.5)
                                                                                                                        and ((#s575 <= 0.5)
                                                                                                                          and ((#s576 <= 0.5)
                                                                                                                            and ((#s216 <= 1.0)
                                                                                                                              and ((#s78 <= 0.5)
                                                                                                                                and ((#s42 <= 0.5)
                                                                                                                                  and ((#s543 <= 0.5)
                                                                                                                                    and ((filesize <= 169776.0)
                                                                                                                                      and ((#s582 <= 0.5)
                                                                                                                                        and ((#s106 <= 0.5)
                                                                                                                                          and ((#s66 <= 0.5)
                                                                                                                                            and ((#s82 <= 0.5)
                                                                                                                                              and ((#s69 <= 0.5)
                                                                                                                                                and ((#s81 <= 1.0)
                                                                                                                                                  and ((#s113 <= 1.0)
                                                                                                                                                    and ((#s589 <= 0.5)
                                                                                                                                                      and ((#s105 <= 0.5)
                                                                                                                                                        and ((#s281 <= 0.5)
                                                                                                                                                          and ((#s592 <= 0.5)
                                                                                                                                                            and ((#s223 <= 1.0)
                                                                                                                                                              and ((#s67 <= 0.5)
                                                                                                                                                                and ((#s495 <= 0.5)
                                                                                                                                                                  and ((#s47 <= 1.0)
                                                                                                                                                                    and ((#s213 <= 0.5)
                                                                                                                                                                      and ((#s455 <= 0.5)
                                                                                                                                                                        and ((#s599 <= 0.5)
                                                                                                                                                                          and ((#s43 <= 0.5)
                                                                                                                                                                            and ((#s117 <= 0.5)
                                                                                                                                                                              and ((#s602 <= 1.0)
                                                                                                                                                                                and ((#s603 <= 0.5)
                                                                                                                                                                                  and ((#s94 <= 0.5)
                                                                                                                                                                                    and ((#s90 <= 1.0)
                                                                                                                                                                                      and ((#s52 <= 0.5)
                                                                                                                                                                                        and ((#s76 <= 0.5)
                                                                                                                                                                                          and ((#s63 <= 0.5)
                                                                                                                                                                                            and ((filesize <= 100238.0)
                                                                                                                                                                                              and ((#s610 <= 1.0)
                                                                                                                                                                                                and ((#s62 <= 1.0)
                                                                                                                                                                                                  and ((filesize <= 99206.0)
                                                                                                                                                                                                    and ((#s79 <= 1.0)
                                                                                                                                                                                                      and ((#s88 <= 0.5)
                                                                                                                                                                                                        and ((filesize <= 79752.0)
                                                                                                                                                                                                          and ((#s205 <= 1.0)
                                                                                                                                                                                                            and ((#s617 <= 1.0)
                                                                                                                                                                                                              and ((filesize > 79704.0)
                                                                                                                                                                                                              )))))) or (filesize > 99206.0)
                                                                                                                                                                                                  ))))))))))))))))))))))))))))))) or (filesize > 169776.0)
                                                                                                                                      and ((#s389 <= 1.0)
                                                                                                                                        and ((#s658 <= 1.0)
                                                                                                                                          and ((#s113 <= 1.0)
                                                                                                                                            and ((#s119 <= 0.5)
                                                                                                                                              and ((#s69 <= 0.5)
                                                                                                                                                and ((filesize <= 174744.0)
                                                                                                                                                  and ((#s47 <= 1.0)
                                                                                                                                                    and ((filesize <= 173138.0)
                                                                                                                                                      and ((filesize <= 170620.0)
                                                                                                                                                      ) or (filesize > 173138.0)
                                                                                                                                                    ))))) or (#s113 > 1.0)
                                                                                                                                            and ((#s86 <= 2.5)
                                                                                                                                            ))))))))))))))) or (#s570 > 0.5)
                                                                                                              ) or (filesize > 457316.0)
                                                                                                              and ((#s342 <= 0.5)
                                                                                                                and ((#s119 <= 1.5)
                                                                                                                  and ((#s82 <= 0.5)
                                                                                                                    and ((#s12 <= 0.5)
                                                                                                                      and ((#s693 <= 62.0)
                                                                                                                        and ((#s62 <= 0.5)
                                                                                                                          and ((#s502 <= 0.5)
                                                                                                                            and ((#s696 <= 2.0)
                                                                                                                              and ((#s697 <= 0.5)
                                                                                                                                and ((#s698 <= 1.0)
                                                                                                                                  and ((#s699 <= 2.0)
                                                                                                                                    and ((#s193 <= 0.5)
                                                                                                                                      and ((#s111 <= 0.5)
                                                                                                                                        and ((#s43 <= 1.0)
                                                                                                                                          and ((#s703 <= 0.5)
                                                                                                                                            and ((#s704 <= 0.5)
                                                                                                                                              and ((filesize <= 459678.0)
                                                                                                                                                or (filesize > 459678.0)
                                                                                                                                                and ((#s56 <= 0.5)
                                                                                                                                                  and ((#s94 <= 1.5)
                                                                                                                                                    and ((#s709 <= 1.0)
                                                                                                                                                      and ((#s198 <= 0.5)
                                                                                                                                                        and ((#s107 <= 1.0)
                                                                                                                                                          and ((#s712 <= 0.5)
                                                                                                                                                            and ((#s536 <= 0.5)
                                                                                                                                                              and ((#s47 <= 1.0)
                                                                                                                                                                and ((#s117 <= 1.0)
                                                                                                                                                                  and ((#s99 <= 1.0)
                                                                                                                                                                    and ((#s717 <= 0.5)
                                                                                                                                                                      and ((#s33 <= 0.5)
                                                                                                                                                                        and ((#s116 <= 0.5)
                                                                                                                                                                          and ((#s90 <= 1.5)
                                                                                                                                                                            and ((#s721 <= 1.0)
                                                                                                                                                                              and ((#s722 <= 0.5)
                                                                                                                                                                                and ((#s723 <= 2.0)
                                                                                                                                                                                  and ((#s122 <= 1.0)
                                                                                                                                                                                    and ((#s52 <= 0.5)
                                                                                                                                                                                      and ((#s86 <= 0.5)
                                                                                                                                                                                        and ((#s180 <= 0.5)
                                                                                                                                                                                          and ((#s728 <= 0.5)
                                                                                                                                                                                            and ((filesize <= 624454.0)
                                                                                                                                                                                              and ((#s57 <= 0.5)
                                                                                                                                                                                                and ((#s207 <= 0.5)
                                                                                                                                                                                                  and ((filesize <= 615196.0)
                                                                                                                                                                                                    and ((filesize <= 467548.0)
                                                                                                                                                                                                      and ((filesize > 465502.0)
                                                                                                                                                                                                      )) or (filesize > 615196.0)
                                                                                                                                                                                                  ))) or (filesize > 624454.0)
                                                                                                                                                                                              and ((#s213 <= 1.5)
                                                                                                                                                                                                and ((#s742 <= 0.5)
                                                                                                                                                                                                  and ((#s743 <= 0.5)
                                                                                                                                                                                                    and ((#s207 <= 0.5)
                                                                                                                                                                                                      and ((filesize > 1677491.5)
                                                                                                                                                                                                        and ((filesize <= 1724018.5)
                                                                                                                                                                                                          or (filesize > 1724018.5)
                                                                                                                                                                                                          and ((filesize <= 1923125.5)
                                                                                                                                                                                                            and ((filesize > 1866227.5)
                                                                                                                                                                                                            )))))))))))))))))))))) or (#s117 > 1.0)
                                                                                                                                                                  and ((#s94 <= 0.5)
                                                                                                                                                                    and ((#s119 <= 0.5)
                                                                                                                                                                      and ((filesize <= 624612.0)
                                                                                                                                                                      )))))) or (#s712 > 0.5)
                                                                                                                                                          ))) or (#s709 > 1.0)
                                                                                                                                                    ) or (#s94 > 1.5)
                                                                                                                                                    and ((#s592 <= 0.5)
                                                                                                                                                      and ((filesize > 2602488.0)
                                                                                                                                                        and ((#s187 <= 1.0)
                                                                                                                                                        ))))))) or (#s703 > 0.5)
                                                                                                                                          ) or (#s43 > 1.0)
                                                                                                                                          and ((filesize > 2068452.0)
                                                                                                                                            and ((filesize <= 3698716.0)
                                                                                                                                            ))) or (#s111 > 0.5)
                                                                                                                                        and ((#s799 <= 0.5)
                                                                                                                                          and ((#s709 > 1.0)
                                                                                                                                          ))))) or (#s698 > 1.0)
                                                                                                                                )))))))))))))) or (#s565 > 0.5)
                                                                                                      and ((#s478 <= 0.5)
                                                                                                        and ((#s74 <= 0.5)
                                                                                                          and ((#s65 <= 0.5)
                                                                                                            and ((#s111 > 0.5)
                                                                                                              and ((#s824 <= 0.5)
                                                                                                                and ((#s207 <= 0.5)
                                                                                                                  and ((#s567 <= 0.5)
                                                                                                                    and ((#s106 <= 0.5)
                                                                                                                      and ((#s69 <= 1.5)
                                                                                                                        and ((#s117 > 0.5)
                                                                                                                          and ((#s831 <= 1.0)
                                                                                                                          )))))))))))) or (#s45 > 0.5)
                                                                                                    and ((#s65 <= 0.5)
                                                                                                      and ((#s47 <= 2.5)
                                                                                                        and ((#s831 <= 0.5)
                                                                                                          and ((#s111 <= 0.5)
                                                                                                            and ((#s846 <= 0.5)
                                                                                                              and ((#s119 > 1.5)
                                                                                                                and ((#s56 <= 1.0)
                                                                                                                  and ((#s575 <= 0.5)
                                                                                                                    and ((#s502 <= 0.5)
                                                                                                                      and ((filesize <= 463569.5)
                                                                                                                        and ((#s122 <= 2.0)
                                                                                                                          and ((#s205 <= 1.0)
                                                                                                                            and ((#s82 <= 0.5)
                                                                                                                              and ((filesize > 444223.5)
                                                                                                                              ))))))))) or (#s846 > 0.5)
                                                                                                              and ((#s76 > 3.0)
                                                                                                                and ((#s728 <= 0.5)
                                                                                                                ))) or (#s111 > 0.5)
                                                                                                            and ((#s717 > 0.5)
                                                                                                              and ((#s117 <= 1.0)
                                                                                                                and ((#s107 <= 1.0)
                                                                                                                )))) or (#s831 > 0.5)
                                                                                                          and ((#s878 <= 0.5)
                                                                                                            and ((#s592 <= 0.5)
                                                                                                              and ((#s207 > 0.5)
                                                                                                                and ((#s52 > 1.0)
                                                                                                                ))))) or (#s47 > 2.5)
                                                                                                        and ((#s57 > 0.5)
                                                                                                        )) or (#s65 > 0.5)
                                                                                                      and ((#s429 > 0.5)
                                                                                                        and ((#s892 > 0.5)
                                                                                                        )))) or (#s563 > 0.5)
                                                                                                ) or (#s115 > 0.5)
                                                                                                and ((#s341 <= 0.5)
                                                                                                  and ((#s87 <= 0.5)
                                                                                                    and ((#s96 <= 0.5)
                                                                                                      and ((#s899 <= 0.5)
                                                                                                        and ((#s62 <= 1.5)
                                                                                                          and ((#s81 <= 0.5)
                                                                                                            and ((#s180 <= 1.0)
                                                                                                              and ((#s565 <= 0.5)
                                                                                                                and ((#s79 <= 1.0)
                                                                                                                  and ((#s92 <= 0.5)
                                                                                                                    and ((filesize <= 319432.0)
                                                                                                                      and ((#s42 <= 0.5)
                                                                                                                        and ((#s908 <= 0.5)
                                                                                                                          and ((#s107 <= 1.0)
                                                                                                                            and ((#s846 <= 0.5)
                                                                                                                              and ((#s117 <= 1.0)
                                                                                                                                and ((#s912 <= 0.5)
                                                                                                                                  and ((#s62 <= 0.5)
                                                                                                                                    and ((#s219 <= 0.5)
                                                                                                                                      and ((#s915 <= 0.5)
                                                                                                                                        and ((#s47 <= 0.5)
                                                                                                                                          and ((#s122 <= 1.0)
                                                                                                                                            and ((#s119 <= 0.5)
                                                                                                                                              and ((#s919 <= 1.0)
                                                                                                                                                and ((#s205 <= 0.5)
                                                                                                                                                  and ((#s103 <= 2.0)
                                                                                                                                                    and ((#s495 <= 1.0)
                                                                                                                                                      and ((#s115 > 1.5)
                                                                                                                                                        and ((filesize > 318320.0)
                                                                                                                                                        )))))))))))))))) or (#s908 > 0.5)
                                                                                                                        )))))))) or (#s62 > 1.5)
                                                                                                          and ((#s103 <= 1.0)
                                                                                                            and ((#s107 > 1.0)
                                                                                                              and ((#s953 > 0.5)
                                                                                                              )))) or (#s899 > 0.5)
                                                                                                        and ((#s565 <= 1.0)
                                                                                                          or (#s565 > 1.0)
                                                                                                          and ((#s959 > 0.5)
                                                                                                          ))))) or (#s341 > 0.5)
                                                                                                  and ((#s964 <= 0.5)
                                                                                                    and ((#s965 <= 0.5)
                                                                                                      and ((#s117 <= 1.0)
                                                                                                        and ((#s967 > 0.5)
                                                                                                        )))))))) or (#s559 > 1.5)
                                                                                        ) or (#s558 > 0.5)
                                                                                        and ((#s976 <= 0.5)
                                                                                          and ((#s121 <= 0.5)
                                                                                            and ((#s919 <= 0.5)
                                                                                              and ((#s979 <= 0.5)
                                                                                                and ((#s557 <= 0.5)
                                                                                                  and ((#s56 <= 0.5)
                                                                                                    and ((#s214 <= 0.5)
                                                                                                      and ((#s560 <= 0.5)
                                                                                                        and ((#s984 <= 0.5)
                                                                                                          and ((#s985 > 0.5)
                                                                                                          ))))) or (#s557 > 0.5)
                                                                                                ) or (#s979 > 0.5)
                                                                                              ))) or (#s976 > 0.5)
                                                                                          and ((#s37 > 1.5)
                                                                                            and ((#s92 <= 0.5)
                                                                                            )))) or (#s557 > 2.0)
                                                                                      and ((#s45 <= 2.0)
                                                                                        and ((#s558 <= 0.5)
                                                                                        ))) or (#s556 > 1.0)
                                                                                  ) or (#s555 > 1.0)
                                                                                ) or (#s554 > 2.0)
                                                                              )) or (#s35 > 0.5)
                                                                            and ((#s119 <= 0.5)
                                                                              and ((#s478 <= 0.5)
                                                                                and ((#s207 <= 0.5)
                                                                                  and ((#s147 <= 0.5)
                                                                                    and ((filesize <= 21498.0)
                                                                                      or (filesize > 21498.0)
                                                                                      and ((#s113 <= 1.0)
                                                                                        and ((#s45 <= 1.0)
                                                                                          and ((#s35 <= 4.5)
                                                                                            and ((filesize > 423737.0)
                                                                                            )))))))))) or (#s34 > 1.5)
                                                                          and ((#s454 <= 1.0)
                                                                            and ((#s122 <= 27.0)
                                                                              and ((#s1030 <= 0.5)
                                                                                and ((#s87 <= 0.5)
                                                                                  and ((#s456 <= 1.5)
                                                                                    and ((#s1033 > 0.5)
                                                                                    )))) or (#s122 > 27.0)
                                                                              and ((#s37 <= 1.0)
                                                                                and ((#s1040 <= 1.0)
                                                                                  and ((#s86 <= 3.5)
                                                                                    and ((#s121 <= 1.5)
                                                                                      and ((#s1043 <= 1.0)
                                                                                        and ((#s223 <= 1.0)
                                                                                        )) or (#s121 > 1.5)
                                                                                      and ((#s57 <= 0.5)
                                                                                        and ((#s1049 <= 1.0)
                                                                                        ) or (#s57 > 0.5)
                                                                                        and ((#s592 <= 1.5)
                                                                                          and ((#s207 > 1.0)
                                                                                          ) or (#s592 > 1.5)
                                                                                        )))) or (#s1040 > 1.0)
                                                                                ))))) or (#s33 > 1.5)
                                                                        and ((#s456 <= 2.5)
                                                                          and ((#s1062 <= 0.5)
                                                                            and ((#s1063 <= 0.5)
                                                                              and ((#s1064 <= 0.5)
                                                                                and ((#s610 <= 0.5)
                                                                                  and ((#s107 <= 0.5)
                                                                                    and ((#s120 <= 0.5)
                                                                                      and ((#s43 <= 0.5)
                                                                                        and ((#s1069 > 0.5)
                                                                                          and ((#s98 <= 0.5)
                                                                                            and ((#s96 > 1.5)
                                                                                              and ((#s1074 > 0.5)
                                                                                              )) or (#s98 > 0.5)
                                                                                          ))) or (#s120 > 0.5)
                                                                                      and ((#s37 > 1.0)
                                                                                        and ((#s62 <= 3.0)
                                                                                          and ((#s1082 > 0.5)
                                                                                          ))))))) or (#s1063 > 0.5)
                                                                              and ((#s1089 > 0.5)
                                                                              )) or (#s1062 > 0.5)
                                                                            and ((filesize <= 8136760.0)
                                                                            )) or (#s456 > 2.5)
                                                                          and ((#s743 > 1.0)
                                                                          ))) or (#s32 > 0.5)
                                                                    ) or (#s31 > 1.5)
                                                                    and ((#s599 <= 0.5)
                                                                      and ((#s1100 <= 1.0)
                                                                        and ((#s456 <= 0.5)
                                                                          and ((#s696 <= 2.0)
                                                                            and ((#s561 <= 0.5)
                                                                              and ((#s1064 <= 0.5)
                                                                                and ((#s346 <= 0.5)
                                                                                  and ((#s47 <= 1.0)
                                                                                    and ((#s60 <= 3.5)
                                                                                      and ((#s117 <= 3.0)
                                                                                        and ((#s1109 <= 0.5)
                                                                                          and ((#s79 <= 1.0)
                                                                                            and ((#s582 <= 1.0)
                                                                                              and ((#s1112 <= 0.5)
                                                                                                and ((#s592 <= 0.5)
                                                                                                  and ((#s1114 <= 0.5)
                                                                                                    and ((#s1115 <= 0.5)
                                                                                                      and ((#s62 <= 0.5)
                                                                                                        and ((#s43 > 1.0)
                                                                                                          and ((#s1119 <= 1.5)
                                                                                                            and ((#s1119 <= 0.5)
                                                                                                              and ((filesize <= 26564.0)
                                                                                                                and ((filesize > 8760.0)
                                                                                                                ))) or (#s1119 > 1.5)
                                                                                                            and ((filesize <= 14024.0)
                                                                                                              and ((filesize <= 12038.0)
                                                                                                                and ((filesize > 10528.0)
                                                                                                                )) or (filesize > 14024.0)
                                                                                                              and ((filesize > 16072.0)
                                                                                                                and ((filesize <= 18120.0)
                                                                                                                ))))) or (#s62 > 0.5)
                                                                                                      ) or (#s1115 > 0.5)
                                                                                                    ))) or (#s1112 > 0.5)
                                                                                              ))) or (#s1109 > 0.5)
                                                                                          and ((filesize <= 1348088.0)
                                                                                            and ((filesize <= 1136760.0)
                                                                                              and ((#s1153 <= 0.5)
                                                                                              )) or (filesize > 1348088.0)
                                                                                          )))))))))) or (#s1100 > 1.0)
                                                                      ))) or (#s30 > 0.5)
                                                                ) or (#s29 > 0.5)
                                                              ) or (#s28 > 0.5)
                                                            ) or (#s27 > 0.5)
                                                          ) or (#s26 > 0.5)
                                                        ) or (#s25 > 0.5)
                                                      ) or (#s24 > 0.5)
                                                    ) or (#s23 > 0.5)
                                                    and ((#s92 > 0.5)
                                                    )) or (#s22 > 0.5)
                                                ) or (#s21 > 0.5)
                                              ) or (#s20 > 0.5)
                                            ) or (#s19 > 0.5)
                                          ) or (#s18 > 0.5)
                                        ) or (#s17 > 0.5)
                                      ) or (#s16 > 0.5)
                                    ) or (#s15 > 0.5)
                                  ) or (#s14 > 1.0)
                                ) or (#s13 > 0.5)
                                and ((#s1187 <= 0.5)
                                  and ((#s1188 <= 0.5)
                                    and ((#s47 <= 1.0)
                                      and ((#s219 <= 0.5)
                                        and ((#s976 <= 0.5)
                                          and ((#s1192 <= 0.5)
                                            and ((#s67 <= 1.0)
                                              and ((#s1194 <= 0.5)
                                                and ((#s98 <= 0.5)
                                                  and ((#s85 <= 0.5)
                                                    and ((#s115 > 1.0)
                                                    ))) or (#s1194 > 0.5)
                                                and ((#s964 <= 0.5)
                                                  and ((#s1203 <= 0.5)
                                                    and ((#s223 <= 1.0)
                                                      and ((#s1074 > 0.5)
                                                      )) or (#s1203 > 0.5)
                                                    and ((#s342 > 0.5)
                                                    )) or (#s964 > 0.5)
                                                  and ((#s425 <= 1.0)
                                                    and ((#s99 > 0.5)
                                                    )))) or (#s67 > 1.0)
                                              and ((#s1069 > 0.5)
                                                and ((#s1219 > 1.0)
                                                ))) or (#s1192 > 0.5)
                                          ) or (#s976 > 0.5)
                                          and ((#s117 <= 1.0)
                                            and ((#s1224 > 3.0)
                                            ) or (#s117 > 1.0)
                                          )) or (#s219 > 0.5)
                                        and ((#s106 <= 0.5)
                                          and ((#s561 <= 0.5)
                                            and ((filesize <= 33368.0)
                                            ) or (#s561 > 0.5)
                                          ) or (#s106 > 0.5)
                                        )) or (#s47 > 1.0)
                                      and ((#s1235 <= 1.0)
                                        and ((#s41 > 0.5)
                                          and ((#s570 > 0.5)
                                          )) or (#s1235 > 1.0)
                                        and ((#s1241 > 0.5)
                                        ))) or (#s1188 > 0.5)
                                    and ((#s1244 <= 0.5)
                                      and ((#s1245 <= 0.5)
                                        and ((#s1246 > 0.5)
                                        )) or (#s1244 > 0.5)
                                      and ((#s1250 > 14.5)
                                      ))) or (#s1187 > 0.5)
                                  and ((#s1253 > 0.5)
                                    and ((#s1255 <= 1.5)
                                      and ((#s69 > 1.0)
                                        and ((#s1258 <= 1.0)
                                        )))))) or (#s12 > 2.5)
                              and ((#s1262 <= 2.0)
                                and ((#s567 > 1.0)
                                  and ((#s214 > 1.0)
                                  )))) or (#s11 > 0.5)
                          ) or (#s10 > 1.5)
                          and ((#s117 <= 1.0)
                            and ((filesize <= 37640.5)
                              or (filesize > 37640.5)
                              and ((#s33 > 1.5)
                                and ((#s1275 <= 1.5)
                                ))) or (#s117 > 1.0)
                            and ((#s98 > 1.5)
                              and ((#s92 > 2.0)
                              )))) or (#s9 > 0.5)
                      ) or (#s8 > 0.5)
                      and ((#s1284 <= 0.5)
                        and ((#s1285 <= 0.5)
                          and ((#s73 <= 0.5)
                            and ((#s1287 <= 0.5)
                              and ((#s1288 <= 0.5)
                                and ((#s1289 > 0.5)
                                  and ((#s1291 <= 0.5)
                                    and ((#s60 <= 0.5)
                                      and ((#s575 <= 1.5)
                                        and ((#s1114 > 0.5)
                                          and ((#s115 > 0.5)
                                            and ((#s878 > 1.0)
                                            ))) or (#s575 > 1.5)
                                        and ((#s99 <= 0.5)
                                          and ((#s103 <= 1.0)
                                            or (#s103 > 1.0)
                                            and ((#s106 <= 0.5)
                                              and ((#s65 > 0.5)
                                              ))))) or (#s60 > 0.5)
                                      and ((#s1310 > 0.5)
                                        and ((#s180 <= 1.0)
                                          and ((filesize <= 10092017.0)
                                          )))) or (#s1291 > 0.5)
                                    and ((#s1317 <= 2.5)
                                    ))) or (#s1288 > 0.5)
                              ))) or (#s1285 > 0.5)
                        ) or (#s1284 > 0.5)
                      )) or (#s7 > 0.5)
                    and ((#s1325 <= 0.5)
                      and ((#s1326 <= 9.0)
                        or (#s1326 > 9.0)
                        and ((#s1328 <= 1.0)
                        )) or (#s1325 > 0.5)
                    )) or (#s6 > 0.5)
                ) or (#s5 > 2.0)
              ) or (#s4 > 0.5)
            ) or (#s3 > 1.5)
            and ((#s147 <= 0.5)
              and ((#s1336 <= 0.5)
                and ((#s346 <= 0.5)
                  and ((#s1338 <= 5.0)
                    and ((#s60 > 0.5)
                      and ((#s1341 > 0.5)
                      )))) or (#s1336 > 0.5)
                and ((#s350 <= 0.5)
                )) or (#s147 > 0.5)
              and ((#s1235 > 1.0)
                and ((#s47 <= 1.0)
                )))) or (#s2 > 0.5)
          and ((#s1354 <= 1.0)
            and ((#s78 <= 2.5)
              and ((#s1356 <= 0.5)
                and ((#s1357 <= 1.0)
                ) or (#s1356 > 0.5)
              ) or (#s78 > 2.5)
              and ((#s12 <= 1.0)
              )) or (#s1354 > 1.0)
            and ((#s1364 > 1.0)
            ))) or (#s1 > 3.5)
        and ((#s1367 <= 1.0)
          and ((#s1368 <= 0.5)
            and ((#s341 <= 0.5)
              and ((#s1370 <= 2.5)
                and ((#s1371 > 0.5)
                  and ((#s1373 <= 2.5)
                    and ((#s1374 <= 0.5)
                      and ((#s1375 <= 0.5)
                        and ((#s1376 <= 1.0)
                          and ((#s1377 <= 0.5)
                            and ((#s985 <= 0.5)
                              and ((#s478 <= 0.5)
                                and ((#s1380 <= 1.0)
                                  or (#s1380 > 1.0)
                                  and ((#s1382 <= 2.0)
                                    and ((#s1383 <= 0.5)
                                      and ((#s52 <= 2.5)
                                        and ((#s221 <= 2.0)
                                          and ((#s115 > 1.5)
                                            and ((#s72 <= 0.5)
                                              and ((#s1371 > 2.5)
                                                and ((#s1391 <= 3.0)
                                                  and ((#s1262 <= 1.0)
                                                    and ((#s346 <= 0.5)
                                                      and ((#s1394 > 1.5)
                                                        and ((#s67 <= 1.0)
                                                          and ((#s115 <= 3.0)
                                                            and ((#s1398 <= 1.0)
                                                              and ((#s47 > 1.0)
                                                              )))))))))))) or (#s52 > 2.5)
                                        and ((#s219 <= 0.5)
                                          and ((#s1411 <= 0.5)
                                            and ((#s1412 > 1.5)
                                              and ((#s87 <= 0.5)
                                                and ((#s1415 <= 3.0)
                                                  and ((#s79 > 1.0)
                                                    and ((#s1418 <= 1.0)
                                                      and ((#s572 <= 1.0)
                                                        and ((#s976 <= 0.5)
                                                          and ((#s1421 <= 1.0)
                                                            and ((#s1246 > 0.5)
                                                            )))))))))) or (#s219 > 0.5)
                                          and ((filesize <= 168024.0)
                                            and ((#s1433 <= 1.0)
                                              or (#s1433 > 1.0)
                                              and ((#s67 > 1.0)
                                              ))))) or (#s1383 > 0.5)
                                    ) or (#s1382 > 2.0)
                                  )) or (#s478 > 0.5)
                                and ((#s1441 <= 1.0)
                                  and ((#s1442 <= 1.0)
                                    and ((#s1443 <= 1.5)
                                      and ((#s1219 <= 1.0)
                                        and ((#s1445 <= 0.5)
                                          and ((#s1446 <= 1.5)
                                            and ((#s728 <= 0.5)
                                              and ((#s96 > 2.0)
                                                and ((#s1450 <= 0.5)
                                                  and ((#s286 <= 1.0)
                                                    and ((#s87 <= 0.5)
                                                    )) or (#s1450 > 0.5)
                                                  and ((#s86 > 0.5)
                                                    and ((#s1398 > 0.5)
                                                    )))))))) or (#s1443 > 1.5)
                                      and ((#s1241 <= 1.0)
                                        and ((#s351 > 1.0)
                                          and ((#s1468 > 0.5)
                                          )))) or (#s1442 > 1.0)
                                  ))) or (#s985 > 0.5)
                              and ((#s1474 <= 0.5)
                                and ((#s1468 <= 0.5)
                                  and ((#s99 <= 0.5)
                                    and ((#s1446 <= 0.5)
                                      and ((#s21 <= 0.5)
                                        and ((#s221 <= 0.5)
                                          and ((#s198 <= 1.0)
                                            and ((#s52 > 2.0)
                                              and ((#s106 <= 0.5)
                                                and ((#s1275 <= 0.5)
                                                  and ((#s147 > 0.5)
                                                    and ((#s1487 > 0.5)
                                                    )) or (#s1275 > 0.5)
                                                  and ((#s1487 <= 0.5)
                                                    and ((#s575 > 2.0)
                                                    ) or (#s1487 > 0.5)
                                                  )))))) or (#s21 > 0.5)
                                      ) or (#s1446 > 0.5)
                                      and ((#s1499 > 0.5)
                                        and ((#s69 <= 0.5)
                                          or (#s69 > 0.5)
                                          and ((#s13 > 1.5)
                                          )))) or (#s99 > 0.5)
                                    and ((#s965 <= 1.5)
                                      and ((#s1507 <= 0.5)
                                        and ((#s1508 <= 0.5)
                                          and ((#s429 <= 0.5)
                                            and ((#s1510 <= 0.5)
                                              and ((#s1511 > 2.0)
                                                and ((#s77 <= 0.5)
                                                  and ((#s1511 <= 3.5)
                                                    and ((#s106 <= 1.5)
                                                    )))) or (#s1510 > 0.5)
                                            ) or (#s429 > 0.5)
                                            and ((#s1521 > 1.0)
                                            )) or (#s1508 > 0.5)
                                        ) or (#s1507 > 0.5)
                                        and ((#s1525 <= 3.0)
                                          and ((#s599 > 0.5)
                                          ) or (#s1525 > 3.0)
                                        )))) or (#s1468 > 0.5)
                                  and ((#s70 <= 1.5)
                                    and ((#s704 <= 1.0)
                                      and ((#s56 <= 1.0)
                                        and ((#s1534 <= 0.5)
                                          and ((#s1535 <= 1.5)
                                            and ((#s1371 <= 1.5)
                                              and ((#s1537 <= 0.5)
                                                and ((#s743 <= 0.5)
                                                  and ((#s219 <= 0.5)
                                                    and ((#s1540 <= 1.0)
                                                      and ((#s567 <= 0.5)
                                                        and ((#s561 <= 2.5)
                                                          and ((#s52 > 2.0)
                                                          ) or (#s561 > 2.5)
                                                        ) or (#s567 > 0.5)
                                                        and ((#s1547 > 0.5)
                                                        )) or (#s1540 > 1.0)
                                                    ) or (#s219 > 0.5)
                                                  ) or (#s743 > 0.5)
                                                ) or (#s1537 > 0.5)
                                                and ((#s566 <= 0.5)
                                                  and ((#s1219 <= 1.0)
                                                    and ((#s13 <= 0.5)
                                                      and ((#s1556 <= 0.5)
                                                      ))) or (#s566 > 0.5)
                                                ))) or (#s1535 > 1.5)
                                            and ((#s1563 <= 1.0)
                                              and ((#s1510 <= 0.5)
                                                and ((#s60 > 1.5)
                                                ) or (#s1510 > 0.5)
                                                and ((#s1288 <= 0.5)
                                                  and ((#s1487 <= 0.5)
                                                    and ((#s566 <= 0.5)
                                                      and ((#s351 <= 1.0)
                                                        and ((#s105 <= 1.0)
                                                        )) or (#s566 > 0.5)
                                                    ) or (#s1487 > 0.5)
                                                    and ((#s346 > 0.5)
                                                    )))) or (#s1563 > 1.0)
                                            )) or (#s1534 > 0.5)
                                          and ((#s1582 > 0.5)
                                            and ((#s1584 > 0.5)
                                              and ((#s1586 <= 0.5)
                                                and ((#s1587 <= 2.0)
                                                  and ((#s187 <= 0.5)
                                                    and ((#s1398 > 0.5)
                                                    ))) or (#s1586 > 0.5)
                                              )))) or (#s56 > 1.0)
                                        and ((#s117 > 1.0)
                                          and ((#s1597 > 0.5)
                                            and ((#s1433 > 1.0)
                                            ))))) or (#s70 > 1.5)
                                    and ((filesize <= 2448856.0)
                                    ))) or (#s1474 > 0.5)
                              )) or (#s1377 > 0.5)
                          ) or (#s1376 > 1.0)
                        ) or (#s1375 > 0.5)
                      ) or (#s1374 > 0.5)
                    ) or (#s1373 > 2.5)
                    and ((#s1611 <= 0.5)
                      and ((#s1612 > 0.5)
                        and ((#s115 > 1.5)
                        )) or (#s1611 > 0.5)
                      and ((#s831 <= 0.5)
                        and ((filesize <= 556318.0)
                        ) or (#s831 > 0.5)
                      )))) or (#s1370 > 2.5)
                and ((#s96 <= 1.5)
                  and ((#s892 > 1.0)
                  ))) or (#s341 > 0.5)
              and ((#s87 <= 0.5)
                and ((#s1535 <= 0.5)
                  and ((#s184 <= 1.0)
                    and ((#s1630 > 0.5)
                      and ((#s1632 <= 11.0)
                        and ((#s1258 <= 1.0)
                          and ((#s1235 > 1.0)
                          )) or (#s1632 > 11.0)
                      )) or (#s184 > 1.0)
                    and ((#s1639 <= 2.0)
                      and ((#s565 <= 3.0)
                        and ((#s1641 <= 1.0)
                          and ((#s561 > 34.5)
                            and ((filesize <= 25358152.0)
                            )) or (#s1641 > 1.0)
                          and ((#s1649 <= 0.5)
                            and ((#s122 <= 59.0)
                              or (#s122 > 59.0)
                              and ((#s1652 <= 0.5)
                              )) or (#s1649 > 0.5)
                          )) or (#s565 > 3.0)
                        and ((#s1656 <= 0.5)
                          and ((#s1109 > 2.5)
                          ) or (#s1656 > 0.5)
                          and ((filesize <= 36664592.0)
                          ))))) or (#s1535 > 0.5)
                  and ((#s1664 <= 12.0)
                    and ((#s1341 <= 0.5)
                      and ((#s67 <= 1.0)
                        and ((#s1188 <= 0.5)
                          and ((#s219 > 0.5)
                            and ((#s575 <= 1.5)
                              and ((#s83 > 0.5)
                                and ((#s104 <= 1.0)
                                )))))) or (#s1341 > 0.5)
                      and ((#s1188 > 0.5)
                      )) or (#s1664 > 12.0)
                    and ((#s65 <= 1.5)
                      and ((#s565 <= 1.0)
                        and ((#s187 > 0.5)
                        ))))) or (#s87 > 0.5)
                and ((#s147 > 0.5)
                  and ((#s116 <= 0.5)
                    and ((filesize <= 205856.0)
                      and ((#s1 <= 4.5)
                        and ((#s1694 <= 0.5)
                          and ((#s1468 > 0.5)
                          ) or (#s1694 > 0.5)
                        )) or (filesize > 205856.0)
                      and ((#s347 <= 0.5)
                        and ((#s1701 <= 1.0)
                          and ((#s1702 <= 1.5)
                            and ((#s1398 <= 0.5)
                            ) or (#s1702 > 1.5)
                          )))))))) or (#s1368 > 0.5)
          ) or (#s1367 > 1.0)
          and ((#s561 <= 13.5)
            and ((#s83 > 0.5)
            )))) or (#s0 > 0.5)
      and ((#s1716 <= 1.5)
        and ((#s1291 <= 0.5)
          and ((#s743 <= 0.5)
            and ((#s92 > 0.5)
              and ((#s1586 > 0.5)
              )) or (#s743 > 0.5)
            and ((#s223 <= 1.0)
              and ((#s1725 <= 1.0)
              ))) or (#s1291 > 0.5)
          and ((#s1729 <= 0.5)
            and ((#s1507 <= 0.5)
              and ((#s1089 <= 0.5)
                and ((#s561 <= 111.0)
                  and ((#s1064 <= 0.5)
                    and ((#s1734 <= 6.5)
                      and ((#s1735 <= 1.5)
                        and ((#s1736 <= 1.5)
                          and ((#s1262 <= 1.0)
                            and ((#s1069 <= 1.0)
                              and ((#s341 <= 0.5)
                                and ((#s350 > 0.5)
                                ))) or (#s1262 > 1.0)
                            and ((#s912 > 0.5)
                            )) or (#s1736 > 1.5)
                        ) or (#s1735 > 1.5)
                      ) or (#s1734 > 6.5)
                    ) or (#s1064 > 0.5)
                    and ((#s1535 <= 2.0)
                      and ((#s1115 <= 0.5)
                        or (#s1115 > 0.5)
                        and ((#s1754 <= 3.0)
                          and ((filesize > 18004136.0)
                          ) or (#s1754 > 3.0)
                          and ((filesize <= 25131192.0)
                            and ((filesize > 25131176.0)
                            ))))))) or (#s1089 > 0.5)
                and ((#s610 <= 0.5)
                  and ((#s1766 <= 0.5)
                    and ((#s119 > 1.0)
                    )) or (#s610 > 0.5)
                  and ((#s1370 <= 0.5)
                  ))) or (#s1507 > 0.5)
              and ((#s26 <= 0.5)
                and ((#s1188 > 0.5)
                  and ((#s13 > 0.5)
                    and ((#s1779 <= 0.5)
                      and ((#s1258 <= 1.0)
                      ) or (#s1779 > 0.5)
                      and ((#s892 > 1.0)
                        and ((#s566 > 1.5)
                        ))))) or (#s26 > 0.5)
              )) or (#s1729 > 0.5)
          )) or (#s1716 > 1.5)
        and ((#s1790 <= 1.0)
          and ((#s567 <= 6.5)
            and ((#s1754 <= 0.5)
              and ((#s566 <= 0.5)
                and ((#s743 > 0.5)
                ) or (#s566 > 0.5)
              ) or (#s1754 > 0.5)
              and ((#s1798 <= 0.5)
                and ((#s97 <= 1.0)
                  and ((#s346 <= 0.5)
                    or (#s346 > 0.5)
                    and ((#s83 <= 2.5)
                      and ((#s1611 <= 0.5)
                        and ((#s99 <= 1.5)
                          or (#s99 > 1.5)
                          and ((#s1806 <= 1.0)
                          )) or (#s1611 > 0.5)
                      )))) or (#s1798 > 0.5)
                and ((#s1556 > 0.5)
                )))))))
}