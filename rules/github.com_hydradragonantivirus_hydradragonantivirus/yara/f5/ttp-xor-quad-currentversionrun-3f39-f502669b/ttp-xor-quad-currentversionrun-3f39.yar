rule TTP_XOR_QUAD_CurrentVersionRun_3f39 {
  strings:
    $key_3f39 = { 6c 56 [2] 48 58 [2] 63 74 [2] 4d 56 [2] 59 4d [2] 56 57 [2] 48 4a [2] 4a 4b [2] 51 4d [2] 4d 4a [2] 51 65 }

  condition:
    any of them
}