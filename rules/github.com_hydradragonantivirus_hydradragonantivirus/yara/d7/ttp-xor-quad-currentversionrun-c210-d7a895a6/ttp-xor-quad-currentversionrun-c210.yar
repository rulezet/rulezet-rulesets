rule TTP_XOR_QUAD_CurrentVersionRun_c210 {
  strings:
    $key_c210 = { 91 7f [2] b5 71 [2] 9e 5d [2] b0 7f [2] a4 64 [2] ab 7e [2] b5 63 [2] b7 62 [2] ac 64 [2] b0 63 [2] ac 4c }

  condition:
    any of them
}