rule PEiD_02062_Setup2Go_Installer_Stub_ {
  meta:
    description = "[Setup2Go Installer Stub]"
    ep_only     = "false"

  strings:
    $a = "[SETUP_INFO]\r\nVer"

  condition:
    $a
}