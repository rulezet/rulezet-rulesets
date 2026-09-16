rule TTP_XOR_QUAD_CurrentVersionRun_e615 {
  strings:
    $key_e615 = { b5 7a [2] 91 74 [2] ba 58 [2] 94 7a [2] 80 61 [2] 8f 7b [2] 91 66 [2] 93 67 [2] 88 61 [2] 94 66 [2] 88 49 }

  condition:
    any of them
}