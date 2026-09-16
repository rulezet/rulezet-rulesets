rule TTP_XOR_QUAD_CurrentVersionRun_e840 {
  strings:
    $key_e840 = { bb 2f [2] 9f 21 [2] b4 0d [2] 9a 2f [2] 8e 34 [2] 81 2e [2] 9f 33 [2] 9d 32 [2] 86 34 [2] 9a 33 [2] 86 1c }

  condition:
    any of them
}