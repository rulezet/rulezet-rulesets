rule Virus_Infector_Win32_Expiro_Gen_7_44 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_44.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81e593fa20c008381cec24e8a95aa24808ec32b99cc8f2a7458e25c313f41407"

  strings:
    $s1  = "Userenv.dll not loaded." fullword wide
    $s2  = "Subscriber thread terminated before the mutex was released. Subscriber unique id: " fullword wide
    $s3  = "GetTokenInformation() failed, error: " fullword wide
    $s4  = "Can't get AddSIDToBoundaryDescriptor() address. " fullword wide
    $s5  = "Can't get AddIntegrityLabelToBoundaryDescriptor() address. " fullword wide
    $s6  = "Can't get DeleteBoundaryDescriptor() address. " fullword wide
    $s7  = "InitializeSecurityDescriptor error: " fullword wide
    $s8  = "SetSecurityDescriptorDacl error: " fullword wide
    $s9  = "SetSecurityDescriptorSacl error: " fullword wide
    $s10 = "OpenPrivateNamespace() failed: already open." fullword wide
    $s11 = "Can't get IERegCreateKeyEx function address" fullword wide
    $s12 = "ESyncHelper quit command" fullword wide
    $s13 = "Can't get CreatePrivateNamespace() address. " fullword wide
    $s14 = "Can't get OpenPrivateNamespace() address. " fullword wide
    $s15 = "Can't get ClosePrivateNamespace() address. " fullword wide
    $s16 = "Subscription already exists. EventId: " fullword wide
    $s17 = "Subscriber thread ended before the subscription was deleted. Subscriber unique id: " fullword wide
    $s18 = "CreateFileMapping error, Name: " fullword wide
    $s19 = "Open private namespace failed. " fullword wide
    $s20 = "set unique param: name = %s, value = %s" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}