rule TTP_XOR_QUAD_CurrentVersionRun_5a0a {
  strings:
    $key_5a0a = { 09 65 [2] 2d 6b [2] 06 47 [2] 28 65 [2] 3c 7e [2] 33 64 [2] 2d 79 [2] 2f 78 [2] 34 7e [2] 28 79 [2] 34 56 }

  condition:
    any of them
}