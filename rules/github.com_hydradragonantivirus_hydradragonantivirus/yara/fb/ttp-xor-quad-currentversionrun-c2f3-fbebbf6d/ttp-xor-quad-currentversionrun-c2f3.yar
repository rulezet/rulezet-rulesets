rule TTP_XOR_QUAD_CurrentVersionRun_c2f3 {
  strings:
    $key_c2f3 = { 91 9c [2] b5 92 [2] 9e be [2] b0 9c [2] a4 87 [2] ab 9d [2] b5 80 [2] b7 81 [2] ac 87 [2] b0 80 [2] ac af }

  condition:
    any of them
}