rule TTP_XOR_QUAD_CurrentVersionRun_671c {
  strings:
    $key_671c = { 34 73 [2] 10 7d [2] 3b 51 [2] 15 73 [2] 01 68 [2] 0e 72 [2] 10 6f [2] 12 6e [2] 09 68 [2] 15 6f [2] 09 40 }

  condition:
    any of them
}