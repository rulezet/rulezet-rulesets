rule TTP_XOR_QUAD_CurrentVersionRun_0c6c {
  strings:
    $key_0c6c = { 5f 03 [2] 7b 0d [2] 50 21 [2] 7e 03 [2] 6a 18 [2] 65 02 [2] 7b 1f [2] 79 1e [2] 62 18 [2] 7e 1f [2] 62 30 }

  condition:
    any of them
}