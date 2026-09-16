import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_113_1_Virus_Hija_235 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_113_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08d1b509451f00201266d1ca734cf8ae37fdeeedde7a1a4550e0750e9e3316a8"
    hash2       = "906c9e4e5ab33e9c806bf6d599c20c12a923b135167ae404a119876bfdae42ab"

  strings:
    $x1  = "  * Downloading from http://download.windowsupdate.com/d/msdownload/update/software/defu/2019/07/mpsigstub_ffb7e023a6e562d401216" ascii
    $x2  = "  = Process: c:\\program files\\windows defender\\MpCmdRun.exe" fullword ascii
    $x3  = "  * Downloading from http://download.windowsupdate.com/d/msdownload/update/software/defu/2019/09/as_base_f9d23c867f448b33ac248dd" ascii
    $x4  = "  * Downloading from http://download.windowsupdate.com/d/msdownload/update/software/defu/2019/09/as_engine_543ce9895ebdb7c2ed2b4" ascii
    $x5  = "  * Downloading from http://download.windowsupdate.com/c/msdownload/update/software/defu/2019/10/as_delta_31d3ec8562d6332ca7ddd8" ascii
    $s6  = "WARNING: Attempted to add URL http://download.windowsupdate.com/d/msdownload/update/others/2019/10/30042029_2d8b593d0f6052089941" ascii
    $s7  = "WARNING: Attempted to add URL http://download.windowsupdate.com/d/msdownload/update/others/2019/10/30042061_1ee4f09953a673002064" ascii
    $s8  = "  * Downloading from http://download.windowsupdate.com/d/msdownload/update/software/defu/2019/07/mpsigstub_ffb7e023a6e562d401216" ascii
    $s9  = "  * Downloading from http://download.windowsupdate.com/d/msdownload/update/software/defu/2019/09/as_base_f9d23c867f448b33ac248dd" ascii
    $s10 = "  * Downloading from http://download.windowsupdate.com/d/msdownload/update/software/defu/2019/09/as_engine_543ce9895ebdb7c2ed2b4" ascii
    $s11 = "  + ServiceId = {9482F4B4-E343-43B6-B170-9A65BC822C77}, Server URL = https://www.update.microsoft.com/v6/ClientWebService/client" ascii
    $s12 = "  * Priority = 3, Interactive = 1, Owner is system = 1, Explicit proxy = 1, Proxy session id = -1, ServiceId = {9482F4B4-E343-43" ascii
    $s13 = "  * Priority = 3, Interactive = 1, Owner is system = 1, Explicit proxy = 1, Proxy session id = -1, ServiceId = {9482F4B4-E343-43" ascii
    $s14 = "  + ServiceId = {9482F4B4-E343-43B6-B170-9A65BC822C77}, Server URL = https://www.update.microsoft.com/v6/ClientWebService/client" ascii
    $s15 = "WARNING: Attempted to add URL http://download.windowsupdate.com/d/msdownload/update/others/2019/10/30042061_1ee4f09953a673002064" ascii
    $s16 = "WARNING: Attempted to add URL http://download.windowsupdate.com/d/msdownload/update/others/2019/10/30042029_2d8b593d0f6052089941" ascii
    $s17 = "  - Download call complete (succeeded = 1, succeeded with errors = 0, failed = 0, unaccounted = 0)" fullword ascii
    $s18 = "  * Downloading from http://download.windowsupdate.com/c/msdownload/update/software/defu/2019/10/as_delta_31d3ec8562d6332ca7ddd8" ascii
    $s19 = "--  END  --  COMAPI: Download [ClientId = Windows Defender]" fullword ascii
    $s20 = "<<-- SUBMITTED -- COMAPI: Download [ClientId = Windows Defender]" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a9192bab5c7c795c7488b69a1853f9c2" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}