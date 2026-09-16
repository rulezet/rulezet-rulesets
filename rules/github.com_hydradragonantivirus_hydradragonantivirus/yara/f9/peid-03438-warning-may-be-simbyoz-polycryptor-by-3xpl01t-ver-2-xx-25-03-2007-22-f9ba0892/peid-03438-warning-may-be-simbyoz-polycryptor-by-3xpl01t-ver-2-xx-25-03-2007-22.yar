rule PEiD_03438_Warning__may_be_SimbyOZ_polycryptor_by_3xpl01t_ver_2_xx__25_03_2007_22_00__ {
  meta:
    description = "[Warning! may be SimbyOZ polycryptor by 3xpl01t ver 2.xx (25.03.2007 22:00)]"
    ep_only     = "true"

  strings:
    $a = { 57 57 8D 7C 24 04 50 B8 00 D0 17 13 AB 58 5F C3 00 00 }

  condition:
    $a
}