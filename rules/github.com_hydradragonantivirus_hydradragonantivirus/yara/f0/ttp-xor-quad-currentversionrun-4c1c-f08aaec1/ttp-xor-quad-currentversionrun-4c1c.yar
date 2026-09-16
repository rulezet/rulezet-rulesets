rule TTP_XOR_QUAD_CurrentVersionRun_4c1c {
  strings:
    $key_4c1c = { 1f 73 [2] 3b 7d [2] 10 51 [2] 3e 73 [2] 2a 68 [2] 25 72 [2] 3b 6f [2] 39 6e [2] 22 68 [2] 3e 6f [2] 22 40 }

  condition:
    any of them
}