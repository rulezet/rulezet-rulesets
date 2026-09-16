rule TTP_XOR_QUAD_CurrentVersionRun_e473 {
  strings:
    $key_e473 = { b7 1c [2] 93 12 [2] b8 3e [2] 96 1c [2] 82 07 [2] 8d 1d [2] 93 00 [2] 91 01 [2] 8a 07 [2] 96 00 [2] 8a 2f }

  condition:
    any of them
}