rule TTP_XOR_QUAD_CurrentVersionRun_d06f {
  strings:
    $key_d06f = { 83 00 [2] a7 0e [2] 8c 22 [2] a2 00 [2] b6 1b [2] b9 01 [2] a7 1c [2] a5 1d [2] be 1b [2] a2 1c [2] be 33 }

  condition:
    any of them
}