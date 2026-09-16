rule TTP_XOR_QUAD_CurrentVersionRun_e433 {
  strings:
    $key_e433 = { b7 5c [2] 93 52 [2] b8 7e [2] 96 5c [2] 82 47 [2] 8d 5d [2] 93 40 [2] 91 41 [2] 8a 47 [2] 96 40 [2] 8a 6f }

  condition:
    any of them
}