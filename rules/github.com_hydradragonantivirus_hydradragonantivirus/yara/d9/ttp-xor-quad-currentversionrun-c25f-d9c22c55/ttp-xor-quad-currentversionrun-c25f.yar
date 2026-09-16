rule TTP_XOR_QUAD_CurrentVersionRun_c25f {
  strings:
    $key_c25f = { 91 30 [2] b5 3e [2] 9e 12 [2] b0 30 [2] a4 2b [2] ab 31 [2] b5 2c [2] b7 2d [2] ac 2b [2] b0 2c [2] ac 03 }

  condition:
    any of them
}