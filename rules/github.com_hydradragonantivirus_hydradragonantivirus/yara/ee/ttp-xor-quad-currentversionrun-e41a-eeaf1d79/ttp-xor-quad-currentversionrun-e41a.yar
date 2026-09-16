rule TTP_XOR_QUAD_CurrentVersionRun_e41a {
  strings:
    $key_e41a = { b7 75 [2] 93 7b [2] b8 57 [2] 96 75 [2] 82 6e [2] 8d 74 [2] 93 69 [2] 91 68 [2] 8a 6e [2] 96 69 [2] 8a 46 }

  condition:
    any of them
}