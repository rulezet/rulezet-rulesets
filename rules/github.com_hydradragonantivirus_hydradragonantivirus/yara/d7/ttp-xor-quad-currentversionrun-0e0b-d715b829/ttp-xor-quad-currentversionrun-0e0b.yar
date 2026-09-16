rule TTP_XOR_QUAD_CurrentVersionRun_0e0b {
  strings:
    $key_0e0b = { 5d 64 [2] 79 6a [2] 52 46 [2] 7c 64 [2] 68 7f [2] 67 65 [2] 79 78 [2] 7b 79 [2] 60 7f [2] 7c 78 [2] 60 57 }

  condition:
    any of them
}