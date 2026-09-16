rule TTP_XOR_QUAD_CurrentVersionRun_0a39 {
  strings:
    $key_0a39 = { 59 56 [2] 7d 58 [2] 56 74 [2] 78 56 [2] 6c 4d [2] 63 57 [2] 7d 4a [2] 7f 4b [2] 64 4d [2] 78 4a [2] 64 65 }

  condition:
    any of them
}