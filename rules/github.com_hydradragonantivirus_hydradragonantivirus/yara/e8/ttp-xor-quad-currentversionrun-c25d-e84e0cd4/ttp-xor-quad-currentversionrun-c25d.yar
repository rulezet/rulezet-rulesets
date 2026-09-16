rule TTP_XOR_QUAD_CurrentVersionRun_c25d {
  strings:
    $key_c25d = { 91 32 [2] b5 3c [2] 9e 10 [2] b0 32 [2] a4 29 [2] ab 33 [2] b5 2e [2] b7 2f [2] ac 29 [2] b0 2e [2] ac 01 }

  condition:
    any of them
}