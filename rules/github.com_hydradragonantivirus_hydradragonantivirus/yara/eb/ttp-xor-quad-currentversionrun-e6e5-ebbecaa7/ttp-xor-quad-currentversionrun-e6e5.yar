rule TTP_XOR_QUAD_CurrentVersionRun_e6e5 {
  strings:
    $key_e6e5 = { b5 8a [2] 91 84 [2] ba a8 [2] 94 8a [2] 80 91 [2] 8f 8b [2] 91 96 [2] 93 97 [2] 88 91 [2] 94 96 [2] 88 b9 }

  condition:
    any of them
}