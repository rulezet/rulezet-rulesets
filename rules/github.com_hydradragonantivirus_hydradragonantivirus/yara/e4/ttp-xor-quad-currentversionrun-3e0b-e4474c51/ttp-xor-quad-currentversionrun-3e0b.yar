rule TTP_XOR_QUAD_CurrentVersionRun_3e0b {
  strings:
    $key_3e0b = { 6d 64 [2] 49 6a [2] 62 46 [2] 4c 64 [2] 58 7f [2] 57 65 [2] 49 78 [2] 4b 79 [2] 50 7f [2] 4c 78 [2] 50 57 }

  condition:
    any of them
}