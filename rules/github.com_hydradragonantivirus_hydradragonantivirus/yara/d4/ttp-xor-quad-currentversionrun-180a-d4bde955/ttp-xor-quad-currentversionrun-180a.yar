rule TTP_XOR_QUAD_CurrentVersionRun_180a {
  strings:
    $key_180a = { 4b 65 [2] 6f 6b [2] 44 47 [2] 6a 65 [2] 7e 7e [2] 71 64 [2] 6f 79 [2] 6d 78 [2] 76 7e [2] 6a 79 [2] 76 56 }

  condition:
    any of them
}