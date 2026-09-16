rule TTP_XOR_QUAD_CurrentVersionRun_e940 {
  strings:
    $key_e940 = { ba 2f [2] 9e 21 [2] b5 0d [2] 9b 2f [2] 8f 34 [2] 80 2e [2] 9e 33 [2] 9c 32 [2] 87 34 [2] 9b 33 [2] 87 1c }

  condition:
    any of them
}