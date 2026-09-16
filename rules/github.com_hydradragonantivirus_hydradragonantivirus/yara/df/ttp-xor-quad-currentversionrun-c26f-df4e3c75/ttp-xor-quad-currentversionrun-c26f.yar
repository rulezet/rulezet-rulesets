rule TTP_XOR_QUAD_CurrentVersionRun_c26f {
  strings:
    $key_c26f = { 91 00 [2] b5 0e [2] 9e 22 [2] b0 00 [2] a4 1b [2] ab 01 [2] b5 1c [2] b7 1d [2] ac 1b [2] b0 1c [2] ac 33 }

  condition:
    any of them
}