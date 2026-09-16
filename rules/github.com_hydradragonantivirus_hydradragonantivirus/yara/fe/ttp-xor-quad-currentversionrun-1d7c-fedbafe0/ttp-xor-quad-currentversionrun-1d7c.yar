rule TTP_XOR_QUAD_CurrentVersionRun_1d7c {
  strings:
    $key_1d7c = { 4e 13 [2] 6a 1d [2] 41 31 [2] 6f 13 [2] 7b 08 [2] 74 12 [2] 6a 0f [2] 68 0e [2] 73 08 [2] 6f 0f [2] 73 20 }

  condition:
    any of them
}