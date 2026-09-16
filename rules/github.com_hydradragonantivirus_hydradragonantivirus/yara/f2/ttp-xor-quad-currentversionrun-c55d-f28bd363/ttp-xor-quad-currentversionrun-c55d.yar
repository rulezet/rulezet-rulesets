rule TTP_XOR_QUAD_CurrentVersionRun_c55d {
  strings:
    $key_c55d = { 96 32 [2] b2 3c [2] 99 10 [2] b7 32 [2] a3 29 [2] ac 33 [2] b2 2e [2] b0 2f [2] ab 29 [2] b7 2e [2] ab 01 }

  condition:
    any of them
}