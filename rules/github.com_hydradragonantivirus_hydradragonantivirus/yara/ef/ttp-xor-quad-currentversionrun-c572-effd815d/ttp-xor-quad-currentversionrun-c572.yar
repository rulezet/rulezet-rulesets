rule TTP_XOR_QUAD_CurrentVersionRun_c572 {
  strings:
    $key_c572 = { 96 1d [2] b2 13 [2] 99 3f [2] b7 1d [2] a3 06 [2] ac 1c [2] b2 01 [2] b0 00 [2] ab 06 [2] b7 01 [2] ab 2e }

  condition:
    any of them
}