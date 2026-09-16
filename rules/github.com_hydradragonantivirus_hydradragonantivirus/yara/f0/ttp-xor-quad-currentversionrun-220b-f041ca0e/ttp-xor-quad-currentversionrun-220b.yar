rule TTP_XOR_QUAD_CurrentVersionRun_220b {
  strings:
    $key_220b = { 71 64 [2] 55 6a [2] 7e 46 [2] 50 64 [2] 44 7f [2] 4b 65 [2] 55 78 [2] 57 79 [2] 4c 7f [2] 50 78 [2] 4c 57 }

  condition:
    any of them
}