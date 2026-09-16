rule TTP_XOR_QUAD_CurrentVersionRun_680a {
  strings:
    $key_680a = { 3b 65 [2] 1f 6b [2] 34 47 [2] 1a 65 [2] 0e 7e [2] 01 64 [2] 1f 79 [2] 1d 78 [2] 06 7e [2] 1a 79 [2] 06 56 }

  condition:
    any of them
}