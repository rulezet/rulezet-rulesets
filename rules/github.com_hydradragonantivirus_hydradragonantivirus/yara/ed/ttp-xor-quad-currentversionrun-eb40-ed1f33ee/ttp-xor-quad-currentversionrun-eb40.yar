rule TTP_XOR_QUAD_CurrentVersionRun_eb40 {
  strings:
    $key_eb40 = { b8 2f [2] 9c 21 [2] b7 0d [2] 99 2f [2] 8d 34 [2] 82 2e [2] 9c 33 [2] 9e 32 [2] 85 34 [2] 99 33 [2] 85 1c }

  condition:
    any of them
}