rule TTP_XOR_QUAD_CurrentVersionRun_1d6d {
  strings:
    $key_1d6d = { 4e 02 [2] 6a 0c [2] 41 20 [2] 6f 02 [2] 7b 19 [2] 74 03 [2] 6a 1e [2] 68 1f [2] 73 19 [2] 6f 1e [2] 73 31 }

  condition:
    any of them
}