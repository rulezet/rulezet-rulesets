rule _Trojan_Danger_Trojan_GenericKD_72853156_56_Virus_Autorun_Trojan_207 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_56.vir, Virus.Autorun_Trojan.GenericKDZ.94942_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f48dc4349b17c5db231be8e38c6e9aa55993614d3ecce977526d872dfe38a50d"
    hash2       = "f424124429184fcce5f03de260e2a123484d1943b89552c527f43cf7d593794c"

  strings:
    $s1  = "ExpressionBuiltEventArgs (RegisteredServiceType: {SimpleInjector.Helpers.ToFriendlyName(RegisteredServiceType),nq}, Expression: " ascii
    $s2  = "ExpressionBuildingEventArgs (RegisteredServiceType: {SimpleInjector.Helpers.ToFriendlyName(RegisteredServiceType),nq}, Expressio" ascii
    $s3  = "ExpressionBuiltEventArgs (RegisteredServiceType: {SimpleInjector.Helpers.ToFriendlyName(RegisteredServiceType),nq}, Expression: " ascii
    $s4  = "Argument: {SimpleInjector.Helpers.ToFriendlyName(Argument),nq}, ConcreteType: {SimpleInjector.Helpers.ToFriendlyName(ConcreteTyp" ascii
    $s5  = "Argument: {SimpleInjector.Helpers.ToFriendlyName(Argument),nq}, ConcreteType: {SimpleInjector.Helpers.ToFriendlyName(ConcreteTyp" ascii
    $s6  = "Alphaleonis.Win32.Filesystem.NativeMethods.GetMappedFileName(System.IntPtr,Alphaleonis.Win32.SafeGlobalMemoryBufferHandle,System" ascii
    $s7  = "4{SimpleInjector.Helpers.ToFriendlyName(Argument),nq}" fullword ascii
    $s8  = "Use the overload that takes SimpleInjector.Container as an argument instead. This method might incorrectly return any decorators" ascii
    $s9  = "Use the overload that takes SimpleInjector.Container as an argument instead. This method might incorrectly return any decorators" ascii
    $s10 = "This method is obsolete and will be removed in a future version. Use Container.GetRegistration().Registration.InitializeInstance" ascii
    $s11 = "This method is obsolete and will be removed in a future version. Use Container.GetRegistration().Registration.InitializeInstance" ascii
    $s12 = "ComPort)" fullword ascii
    $s13 = "{Description,nq}" fullword ascii
    $s14 = "infoSretrieves package information. Shorthand for choco search pkgname --exact --verbose" fullword ascii
    $s15 = "config+Retrieve and configure config file settings" fullword ascii
    $s16 = "source\"view and configure default sources" fullword ascii
    $s17 = "sources5view and configure default sources (alias for source)" fullword ascii
    $s18 = "features5view and configure choco features (alias for feature)" fullword ascii
    $s19 = "setapikeyPretrieves, saves or deletes an apikey for a particular source (alias for apikey)" fullword ascii
    $s20 = "apikey=retrieves, saves or deletes an apikey for a particular source" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}