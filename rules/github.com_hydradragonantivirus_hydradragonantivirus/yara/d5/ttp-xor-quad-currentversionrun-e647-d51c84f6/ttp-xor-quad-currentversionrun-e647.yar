rule TTP_XOR_QUAD_CurrentVersionRun_e647 {
  strings:
    $key_e647 = { b5 28 [2] 91 26 [2] ba 0a [2] 94 28 [2] 80 33 [2] 8f 29 [2] 91 34 [2] 93 35 [2] 88 33 [2] 94 34 [2] 88 1b }

  condition:
    any of them
}