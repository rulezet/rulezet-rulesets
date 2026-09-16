rule TTP_XOR_QUAD_CurrentVersionRun_e64b {
  strings:
    $key_e64b = { b5 24 [2] 91 2a [2] ba 06 [2] 94 24 [2] 80 3f [2] 8f 25 [2] 91 38 [2] 93 39 [2] 88 3f [2] 94 38 [2] 88 17 }

  condition:
    any of them
}