rule TTP_XOR_QUAD_CurrentVersionRun_1d33 {
  strings:
    $key_1d33 = { 4e 5c [2] 6a 52 [2] 41 7e [2] 6f 5c [2] 7b 47 [2] 74 5d [2] 6a 40 [2] 68 41 [2] 73 47 [2] 6f 40 [2] 73 6f }

  condition:
    any of them
}