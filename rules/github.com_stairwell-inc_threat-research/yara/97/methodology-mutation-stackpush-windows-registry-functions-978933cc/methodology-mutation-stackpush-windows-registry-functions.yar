rule Methodology_Mutation_StackPush_Windows_Registry_Functions {
  meta:
    author = "Stairwell"
    description = "Searching for PE files with mutations of odd, rare, or interesting string equities. Here we look for strings from common PE strings, DLLs and functions in type 2 stack strings form, where the string pushed onto the stack 4 bytes at a time using PUSH 0x68, appearing in reverse four byte chunk order, where the PUSH which shows up as an ASCII letter h."
  strings:
    $GetPrivateProfileInt_stackpush = "heInthofilhtePrhrivahGetP" nocase
    $GetPrivateProfileSection_stackpush = "htionheSechofilhtePrhrivahGetP" nocase
    $GetPrivateProfileSectionNames_stackpush = "hshNamehtionheSechofilhtePrhrivahGetP" nocase
    $GetPrivateProfileString_stackpush = "hingheStrhofilhtePrhrivahGetP" nocase
    $GetPrivateProfileStruct_stackpush = "huctheStrhofilhtePrhrivahGetP" nocase
    $GetProfileInt_stackpush = "hthleInhrofihGetP" nocase
    $GetProfileSection_stackpush = "hnhctiohleSehrofihGetP" nocase
    $GetProfileString_stackpush = "hringhleSthrofihGetP" nocase
    $RegCloseKey_stackpush = "hKeyhlosehRegC" nocase
    $RegConnectRegistry_stackpush = "hryhgisthctRehonnehRegC" nocase
    $RegCopyTree_stackpush = "hreehopyThRegC" nocase
    $RegCreateKey_stackpush = "heKeyhreathRegC" nocase
    $RegCreateKeyEx_stackpush = "hExheKeyhreathRegC" nocase
    $RegCreateKeyTransacted_stackpush = "hedhsacthTranheKeyhreathRegC" nocase
    $RegDeleteKey_stackpush = "heKeyhelethRegD" nocase
    $RegDeleteKeyEx_stackpush = "hExheKeyhelethRegD" nocase
    $RegDeleteKeyTransacted_stackpush = "hedhsacthTranheKeyhelethRegD" nocase
    $RegDeleteKeyValue_stackpush = "hehValuheKeyhelethRegD" nocase
    $RegDeleteTree_stackpush = "heheTrehelethRegD" nocase
    $RegDeleteValue_stackpush = "hueheValhelethRegD" nocase
    $RegDisablePredefinedCache_stackpush = "hehCachhinedhedefhlePrhisabhRegD" nocase
    $RegDisablePredefinedCacheEx_stackpush = "heExhCachhinedhedefhlePrhisabhRegD" nocase
    $RegDisableReflectionKey_stackpush = "hKeyhtionhflechleRehisabhRegD" nocase
    $RegEnableReflectionKey_stackpush = "heyhionKhlectheRefhnablhRegE" nocase
    $RegEnumKey_stackpush = "heyhnumKhRegE" nocase
    $RegEnumKeyEx_stackpush = "heyExhnumKhRegE" nocase
    $RegEnumValue_stackpush = "haluehnumVhRegE" nocase
    $RegFlushKey_stackpush = "hKeyhlushhRegF" nocase
    $RegGetValue_stackpush = "hluehetVahRegG" nocase
    $RegLoadAppKey_stackpush = "hyhppKehoadAhRegL" nocase
    $RegLoadKey_stackpush = "heyhoadKhRegL" nocase
    $RegLoadMUIString_stackpush = "hringhUISthoadMhRegL" nocase
    $RegNotifyChangeKeyValue_stackpush = "hlueheyVahngeKhyChahotifhRegN" nocase
    $RegOpenCurrentUser_stackpush = "herhntUshurrehpenChRegO" nocase
    $RegOpenKey_stackpush = "heyhpenKhRegO" nocase
    $RegOpenKeyEx_stackpush = "heyExhpenKhRegO" nocase
    $RegOpenKeyTransacted_stackpush = "hctedhansaheyTrhpenKhRegO" nocase
    $RegOpenUserClassesRoot_stackpush = "hothesRohlasshserChpenUhRegO" nocase
    $RegOverridePredefKey_stackpush = "hfKeyhredehidePhverrhRegO" nocase
    $RegQueryInfoKey_stackpush = "hKeyhInfohueryhRegQ" nocase
    $RegQueryMultipleValues_stackpush = "heshValuhiplehMulthueryhRegQ" nocase
    $RegQueryReflectionKey_stackpush = "hyhonKehectihReflhueryhRegQ" nocase
    $RegQueryValue_stackpush = "hehValuhueryhRegQ" nocase
    $RegQueryValueEx_stackpush = "heExhValuhueryhRegQ" nocase
    $RegReplaceKey_stackpush = "hyhceKeheplahRegR" nocase
    $RegRestoreKey_stackpush = "hyhreKehestohRegR" nocase
    $RegSaveKey_stackpush = "heyhaveKhRegS" nocase
    $RegSaveKeyEx_stackpush = "heyExhaveKhRegS" nocase
    $RegSetKeyValue_stackpush = "huehyValhetKehRegS" nocase
    $RegSetValue_stackpush = "hluehetVahRegS" nocase
    $RegSetValueEx_stackpush = "hxhlueEhetVahRegS" nocase
    $RegUnLoadKey_stackpush = "hdKeyhnLoahRegU" nocase
    $WritePrivateProfileSection_stackpush = "honhectihileShProfhvatehePrihWrit" nocase
    $WritePrivateProfileString_stackpush = "hghtrinhileShProfhvatehePrihWrit" nocase
    $WritePrivateProfileStruct_stackpush = "hthtruchileShProfhvatehePrihWrit" nocase
    $WriteProfileSection_stackpush = "hionhSecthfileheProhWrit" nocase
    $WriteProfileString_stackpush = "hnghStrihfileheProhWrit" nocase
  condition:
    filesize < 5MB and uint16be(0) == 0x4d5a and 1 of them
}