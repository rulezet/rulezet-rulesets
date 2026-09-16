rule TTP_XOR_QUAD_CurrentVersionRun_e47c {
  strings:
    $key_e47c = { b7 13 [2] 93 1d [2] b8 31 [2] 96 13 [2] 82 08 [2] 8d 12 [2] 93 0f [2] 91 0e [2] 8a 08 [2] 96 0f [2] 8a 20 }

  condition:
    any of them
}