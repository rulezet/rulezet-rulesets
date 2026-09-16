rule TTP_XOR_QUAD_CurrentVersionRun_e639 {
  strings:
    $key_e639 = { b5 56 [2] 91 58 [2] ba 74 [2] 94 56 [2] 80 4d [2] 8f 57 [2] 91 4a [2] 93 4b [2] 88 4d [2] 94 4a [2] 88 65 }

  condition:
    any of them
}