rule TTP_XOR_QUAD_CurrentVersionRun_c23f {
  strings:
    $key_c23f = { 91 50 [2] b5 5e [2] 9e 72 [2] b0 50 [2] a4 4b [2] ab 51 [2] b5 4c [2] b7 4d [2] ac 4b [2] b0 4c [2] ac 63 }

  condition:
    any of them
}