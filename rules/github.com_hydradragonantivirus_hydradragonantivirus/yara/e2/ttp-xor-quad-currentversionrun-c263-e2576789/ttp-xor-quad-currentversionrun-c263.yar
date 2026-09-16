rule TTP_XOR_QUAD_CurrentVersionRun_c263 {
  strings:
    $key_c263 = { 91 0c [2] b5 02 [2] 9e 2e [2] b0 0c [2] a4 17 [2] ab 0d [2] b5 10 [2] b7 11 [2] ac 17 [2] b0 10 [2] ac 3f }

  condition:
    any of them
}