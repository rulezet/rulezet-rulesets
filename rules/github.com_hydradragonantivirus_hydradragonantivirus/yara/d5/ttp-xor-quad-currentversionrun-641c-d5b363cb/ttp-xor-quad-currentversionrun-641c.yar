rule TTP_XOR_QUAD_CurrentVersionRun_641c {
  strings:
    $key_641c = { 37 73 [2] 13 7d [2] 38 51 [2] 16 73 [2] 02 68 [2] 0d 72 [2] 13 6f [2] 11 6e [2] 0a 68 [2] 16 6f [2] 0a 40 }

  condition:
    any of them
}