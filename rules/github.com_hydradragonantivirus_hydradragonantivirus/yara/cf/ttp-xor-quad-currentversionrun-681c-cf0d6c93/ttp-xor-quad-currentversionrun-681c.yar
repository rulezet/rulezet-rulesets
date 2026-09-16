rule TTP_XOR_QUAD_CurrentVersionRun_681c {
  strings:
    $key_681c = { 3b 73 [2] 1f 7d [2] 34 51 [2] 1a 73 [2] 0e 68 [2] 01 72 [2] 1f 6f [2] 1d 6e [2] 06 68 [2] 1a 6f [2] 06 40 }

  condition:
    any of them
}