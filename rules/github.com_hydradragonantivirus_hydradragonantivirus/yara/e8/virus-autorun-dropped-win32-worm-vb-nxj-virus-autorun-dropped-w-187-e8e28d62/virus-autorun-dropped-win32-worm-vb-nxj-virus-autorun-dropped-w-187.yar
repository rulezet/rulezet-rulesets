rule _Virus_Autorun_Dropped_Win32_Worm_VB_NXJ_Virus_Autorun_Dropped_W_187 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Dropped.Win32.Worm.VB.NXJ.vir, Virus.Autorun_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b79a57a926f801baca06e13180644ff8a9531494ec2bc0fb219ba35b9e51f5"
    hash2       = "0b5dc186b2c779853a25d3f0d3bc3470a319fb2d976594e000f7f06c23b18e03"
    hash3       = "d6767a4b06185a363a0348866269fb91d958be7963fa9f901ec3f2503d418fef"
    hash4       = "4e62e7a3b77d4d0abb803c175f51d1242fda33bfd3308991b9e90391cac1c369"

  strings:
    $s1  = "CWebServerHandlers::Install m_spAppHostAdminManager->GetAdminSection failed. m_cbstrSectionName=%s m_cbstrConfigCommitPath=%s Er" wide
    $s2  = "CFileHelper::CopyAndReturnTempPath. GetTempPath failed dwRetVal=%d. GetLastError returned 0x%x" fullword wide
    $s3  = "CScriptMapsComponent::Install GetScriptMapsData failed. Error code: 0x%x" fullword wide
    $s4  = "CFxInstaller::SetupScriptMapsIIS7 webServerHandlerComponent.Install failed. c_szRulesExtension=%s Error code: 0x%x" fullword wide
    $s5  = "CFxInstaller::SetupScriptMapsIIS7 webServerHandlerComponent.Install failed. c_szXomlExtension=%s Error code: 0x%x" fullword wide
    $s6  = "CFxInstaller::SetupScriptMapsIIS6 scriptMapsComponent.Install failed. c_szRulesExtension=%s isapiPath=%s c_szScriptOptions=%s Er" wide
    $s7  = "CFxInstaller::SetupScriptMapsIIS6 scriptMapsComponent.Install failed. c_szXomlExtension=%s isapiPath=%s c_szScriptOptions=%s Err" wide
    $s8  = "CFxInstaller::SetupHttpHandlers wsdlImporterExtension.AddToConfigFile() failed. Value=%s. Error code: 0x%x " fullword wide
    $s9  = "CFxInstaller::SetupHttpHandlers policyImporterExtension.AddToConfigFile() failed. Value=%s. Error code: 0x%x " fullword wide
    $s10 = "CFxInstaller::SetupComponents SetupScriptMaps failed. Error code: 0x%x" fullword wide
    $s11 = "CWebServerHandlers::Install m_spAppHostAdminManager->CommitChanges failed. Error code: 0x%x" fullword wide
    $s12 = "CFxInstaller::SetupComponents SetupImporterExtension failed. Error code: 0x%x" fullword wide
    $s13 = "Usage: %s [/c] [/r] [/v] [/m] [/i]" fullword ascii
    $s14 = "    /r(emove):      Remove Windows Workflow Services Configuration." fullword ascii
    $s15 = "    /c(onfigure):   Configure Windows Workflow Services." fullword ascii
    $s16 = "CFxInstaller::SetupHttpHandlers Removing %s." fullword wide
    $s17 = "CFxInstaller::SetupComponents SetupBuilderProvider failed. Error code: 0x%x" fullword wide
    $s18 = "CFxInstaller::SetupComponents SetupHttpHandlers failed. Error code: 0x%x" fullword wide
    $s19 = "CFxInstaller::SetupComponents SetupExtensions failed. Error code: 0x%x" fullword wide
    $s20 = "CFxInstaller::SetupComponents Calling SetupScriptMaps." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}