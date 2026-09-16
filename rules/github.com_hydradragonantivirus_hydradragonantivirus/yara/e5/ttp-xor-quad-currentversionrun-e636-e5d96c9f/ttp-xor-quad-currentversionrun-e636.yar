rule TTP_XOR_QUAD_CurrentVersionRun_e636 {
  strings:
    $key_e636 = { b5 59 [2] 91 57 [2] ba 7b [2] 94 59 [2] 80 42 [2] 8f 58 [2] 91 45 [2] 93 44 [2] 88 42 [2] 94 45 [2] 88 6a }

  condition:
    any of them
}