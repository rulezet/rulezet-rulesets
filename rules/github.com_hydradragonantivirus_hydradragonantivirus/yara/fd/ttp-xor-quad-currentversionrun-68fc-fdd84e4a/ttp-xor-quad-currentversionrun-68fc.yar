rule TTP_XOR_QUAD_CurrentVersionRun_68fc {
  strings:
    $key_68fc = { 3b 93 [2] 1f 9d [2] 34 b1 [2] 1a 93 [2] 0e 88 [2] 01 92 [2] 1f 8f [2] 1d 8e [2] 06 88 [2] 1a 8f [2] 06 a0 }

  condition:
    any of them
}