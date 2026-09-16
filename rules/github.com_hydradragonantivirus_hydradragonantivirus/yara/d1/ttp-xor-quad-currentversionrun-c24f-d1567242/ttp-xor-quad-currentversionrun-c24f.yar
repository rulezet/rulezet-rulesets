rule TTP_XOR_QUAD_CurrentVersionRun_c24f {
  strings:
    $key_c24f = { 91 20 [2] b5 2e [2] 9e 02 [2] b0 20 [2] a4 3b [2] ab 21 [2] b5 3c [2] b7 3d [2] ac 3b [2] b0 3c [2] ac 13 }

  condition:
    any of them
}