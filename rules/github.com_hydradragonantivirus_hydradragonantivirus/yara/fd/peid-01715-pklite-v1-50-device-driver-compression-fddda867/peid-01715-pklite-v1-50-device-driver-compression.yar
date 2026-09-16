rule PEiD_01715_PKLITE_v1_50__Device_driver_compression__ {
  meta:
    description = "[PKLITE v1.50 (Device driver compression)]"
    ep_only     = "true"

  strings:
    $a = { B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB }

  condition:
    $a
}