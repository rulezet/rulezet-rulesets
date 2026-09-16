rule TTP_XOR_QUAD_CurrentVersionRun_e47b {
  strings:
    $key_e47b = { b7 14 [2] 93 1a [2] b8 36 [2] 96 14 [2] 82 0f [2] 8d 15 [2] 93 08 [2] 91 09 [2] 8a 0f [2] 96 08 [2] 8a 27 }

  condition:
    any of them
}