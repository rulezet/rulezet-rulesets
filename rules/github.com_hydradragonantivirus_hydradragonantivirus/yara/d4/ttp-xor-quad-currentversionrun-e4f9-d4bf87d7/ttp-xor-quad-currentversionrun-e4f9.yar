rule TTP_XOR_QUAD_CurrentVersionRun_e4f9 {
  strings:
    $key_e4f9 = { b7 96 [2] 93 98 [2] b8 b4 [2] 96 96 [2] 82 8d [2] 8d 97 [2] 93 8a [2] 91 8b [2] 8a 8d [2] 96 8a [2] 8a a5 }

  condition:
    any of them
}