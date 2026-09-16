rule TTP_XOR_QUAD_CurrentVersionRun_c250 {
  strings:
    $key_c250 = { 91 3f [2] b5 31 [2] 9e 1d [2] b0 3f [2] a4 24 [2] ab 3e [2] b5 23 [2] b7 22 [2] ac 24 [2] b0 23 [2] ac 0c }

  condition:
    any of them
}