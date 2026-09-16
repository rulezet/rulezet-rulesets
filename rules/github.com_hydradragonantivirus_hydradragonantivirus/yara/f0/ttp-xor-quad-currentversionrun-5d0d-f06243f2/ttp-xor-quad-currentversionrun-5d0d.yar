rule TTP_XOR_QUAD_CurrentVersionRun_5d0d {
  strings:
    $key_5d0d = { 0e 62 [2] 2a 6c [2] 01 40 [2] 2f 62 [2] 3b 79 [2] 34 63 [2] 2a 7e [2] 28 7f [2] 33 79 [2] 2f 7e [2] 33 51 }

  condition:
    any of them
}