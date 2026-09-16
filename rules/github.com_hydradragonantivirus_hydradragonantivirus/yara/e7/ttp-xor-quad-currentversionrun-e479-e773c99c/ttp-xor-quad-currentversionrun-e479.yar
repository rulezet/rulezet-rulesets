rule TTP_XOR_QUAD_CurrentVersionRun_e479 {
  strings:
    $key_e479 = { b7 16 [2] 93 18 [2] b8 34 [2] 96 16 [2] 82 0d [2] 8d 17 [2] 93 0a [2] 91 0b [2] 8a 0d [2] 96 0a [2] 8a 25 }

  condition:
    any of them
}