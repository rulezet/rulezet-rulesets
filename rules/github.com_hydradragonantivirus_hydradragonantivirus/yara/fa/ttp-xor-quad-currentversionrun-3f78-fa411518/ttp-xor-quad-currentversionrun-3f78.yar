rule TTP_XOR_QUAD_CurrentVersionRun_3f78 {
  strings:
    $key_3f78 = { 6c 17 [2] 48 19 [2] 63 35 [2] 4d 17 [2] 59 0c [2] 56 16 [2] 48 0b [2] 4a 0a [2] 51 0c [2] 4d 0b [2] 51 24 }

  condition:
    any of them
}