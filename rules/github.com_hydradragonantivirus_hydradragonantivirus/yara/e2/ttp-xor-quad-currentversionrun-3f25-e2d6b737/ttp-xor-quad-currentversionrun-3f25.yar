rule TTP_XOR_QUAD_CurrentVersionRun_3f25 {
  strings:
    $key_3f25 = { 6c 4a [2] 48 44 [2] 63 68 [2] 4d 4a [2] 59 51 [2] 56 4b [2] 48 56 [2] 4a 57 [2] 51 51 [2] 4d 56 [2] 51 79 }

  condition:
    any of them
}