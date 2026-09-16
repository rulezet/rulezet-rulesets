rule TTP_XOR_QUAD_CurrentVersionRun_c220 {
  strings:
    $key_c220 = { 91 4f [2] b5 41 [2] 9e 6d [2] b0 4f [2] a4 54 [2] ab 4e [2] b5 53 [2] b7 52 [2] ac 54 [2] b0 53 [2] ac 7c }

  condition:
    any of them
}