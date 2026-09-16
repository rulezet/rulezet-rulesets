rule PEiD_03433_W32_Jeefo__PE_File_Infector__ {
  meta:
    description = "[W32.Jeefo (PE File Infector)]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 ?? ?? ?? FF D0 E8 ?? ?? ?? ?? C9 C3 }

  condition:
    $a
}