rule libavcodec_8svx_fibonacci__16_lil_32_ {
  strings:
    $a0 = { 00 de 00 eb 00 f3 00 f8 00 fb 00 fd 00 fe 00 ff 00 00 00 01 00 02 00 03 00 05 00 08 00 0d 00 15 }

  condition:
    $a0
}