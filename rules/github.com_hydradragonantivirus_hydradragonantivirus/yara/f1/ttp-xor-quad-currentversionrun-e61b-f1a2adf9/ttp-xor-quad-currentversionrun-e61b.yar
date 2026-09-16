rule TTP_XOR_QUAD_CurrentVersionRun_e61b {
  strings:
    $key_e61b = { b5 74 [2] 91 7a [2] ba 56 [2] 94 74 [2] 80 6f [2] 8f 75 [2] 91 68 [2] 93 69 [2] 88 6f [2] 94 68 [2] 88 47 }

  condition:
    any of them
}