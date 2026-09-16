rule TTP_XOR_QUAD_CurrentVersionRun_1d0c {
  strings:
    $key_1d0c = { 4e 63 [2] 6a 6d [2] 41 41 [2] 6f 63 [2] 7b 78 [2] 74 62 [2] 6a 7f [2] 68 7e [2] 73 78 [2] 6f 7f [2] 73 50 }

  condition:
    any of them
}