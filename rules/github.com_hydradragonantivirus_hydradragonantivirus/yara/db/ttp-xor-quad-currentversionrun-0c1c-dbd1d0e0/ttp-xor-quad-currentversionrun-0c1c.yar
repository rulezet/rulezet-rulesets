rule TTP_XOR_QUAD_CurrentVersionRun_0c1c {
  strings:
    $key_0c1c = { 5f 73 [2] 7b 7d [2] 50 51 [2] 7e 73 [2] 6a 68 [2] 65 72 [2] 7b 6f [2] 79 6e [2] 62 68 [2] 7e 6f [2] 62 40 }

  condition:
    any of them
}