rule Methodology_Mutation_FLIPFLOP_Windows_Registry_Functions {
  meta:
    author = "Stairwell"
    description = "Searching for PE files with mutations of odd, rare, or interesting string equities. This string mutation takes its inspiration from APT29/CozyBear malware family called FLIPFLOP because it reads in a subfile but reverses every two bytes."
    hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
  strings:
    $GetPrivateProfileInt_flipflop = "eGPtiravetrPfoliIetn" nocase
    $GetPrivateProfileSection_flipflop = "eGPtiravetrPfoliSeceitno" nocase
    $GetPrivateProfileSectionNames_flipflop = "eGPtiravetrPfoliSeceitnoaNems" nocase
    $GetPrivateProfileString_flipflop = "eGPtiravetrPfoliSertnig" nocase
    $GetPrivateProfileStruct_flipflop = "eGPtiravetrPfoliSertcut" nocase
    $GetProfileInt_flipflop = "eGPtorifelnIt" nocase
    $GetProfileSection_flipflop = "eGPtorifeleStcoin" nocase
    $GetProfileString_flipflop = "eGPtorifeltSirgn" nocase
    $RegCloseKey_flipflop = "eRCgoleseKy" nocase
    $RegConnectRegistry_flipflop = "eRCgnoentceRigtsyr" nocase
    $RegCopyTree_flipflop = "eRCgpoTyere" nocase
    $RegCreateKey_flipflop = "eRCgertaKeye" nocase
    $RegCreateKeyEx_flipflop = "eRCgertaKeyexE" nocase
    $RegCreateKeyTransacted_flipflop = "eRCgertaKeyerTnaastcde" nocase
    $RegDeleteKey_flipflop = "eRDgleteKeye" nocase
    $RegDeleteKeyEx_flipflop = "eRDgleteKeyexE" nocase
    $RegDeleteKeyTransacted_flipflop = "eRDgleteKeyerTnaastcde" nocase
    $RegDeleteKeyValue_flipflop = "eRDgleteKeyeaVule" nocase
    $RegDeleteTree_flipflop = "eRDgleteTeere" nocase
    $RegDeleteValue_flipflop = "eRDgleteVelaeu" nocase
    $RegDisablePredefinedCache_flipflop = "eRDgsibaelrPdefenideaChce" nocase
    $RegDisablePredefinedCacheEx_flipflop = "eRDgsibaelrPdefenideaChcEex" nocase
    $RegDisableReflectionKey_flipflop = "eRDgsibaeleRlfceitnoeKy" nocase
    $RegEnableReflectionKey_flipflop = "eREganlbRefeeltcoiKnye" nocase
    $RegEnumKey_flipflop = "eREgunKmye" nocase
    $RegEnumKeyEx_flipflop = "eREgunKmyexE" nocase
    $RegEnumValue_flipflop = "eREgunVmlaeu" nocase
    $RegFlushKey_flipflop = "eRFgulhseKy" nocase
    $RegGetValue_flipflop = "eRGgteaVule" nocase
    $RegLoadAppKey_flipflop = "eRLgaoAdppeKy" nocase
    $RegLoadKey_flipflop = "eRLgaoKdye" nocase
    $RegLoadMUIString_flipflop = "eRLgaoMdIUtSirgn" nocase
    $RegNotifyChangeKeyValue_flipflop = "eRNgtofiCyahgnKeyeaVule" nocase
    $RegOpenCurrentUser_flipflop = "eROgepCnruertnsUre" nocase
    $RegOpenKey_flipflop = "eROgepKnye" nocase
    $RegOpenKeyEx_flipflop = "eROgepKnyexE" nocase
    $RegOpenKeyTransacted_flipflop = "eROgepKnyerTnaastcde" nocase
    $RegOpenUserClassesRoot_flipflop = "eROgepUnesCralssseoRto" nocase
    $RegOverridePredefKey_flipflop = "eROgevrrdiPeeredKfye" nocase
    $RegQueryInfoKey_flipflop = "eRQgeuyrnIofeKy" nocase
    $RegQueryMultipleValues_flipflop = "eRQgeuyruMtlpielaVulse" nocase
    $RegQueryReflectionKey_flipflop = "eRQgeuyreRlfceitnoeKy" nocase
    $RegQueryValue_flipflop = "eRQgeuyraVule" nocase
    $RegQueryValueEx_flipflop = "eRQgeuyraVulEex" nocase
    $RegReplaceKey_flipflop = "eRRgpealeceKy" nocase
    $RegRestoreKey_flipflop = "eRRgseotereKy" nocase
    $RegSaveKey_flipflop = "eRSgvaKeye" nocase
    $RegSaveKeyEx_flipflop = "eRSgvaKeyexE" nocase
    $RegSetKeyValue_flipflop = "eRSgteeKVylaeu" nocase
    $RegSetValue_flipflop = "eRSgteaVule" nocase
    $RegSetValueEx_flipflop = "eRSgteaVulEex" nocase
    $RegUnLoadKey_flipflop = "eRUgLnaoKdye" nocase
    $WritePrivateProfileSection_flipflop = "rWtiPeiravetrPfoliSeceitno" nocase
    $WritePrivateProfileString_flipflop = "rWtiPeiravetrPfoliSertnig" nocase
    $WritePrivateProfileStruct_flipflop = "rWtiPeiravetrPfoliSertcut" nocase
    $WriteProfileSection_flipflop = "rWtiPeorifeleStcoin" nocase
    $WriteProfileString_flipflop = "rWtiPeorifeltSirgn" nocase
  condition:
    filesize < 5MB and uint16be(0) == 0x4d5a and 1 of them
}