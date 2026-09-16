rule TTP_XOR_QUAD_CurrentVersionRun_e6f8 {
  strings:
    $key_e6f8 = { b5 97 [2] 91 99 [2] ba b5 [2] 94 97 [2] 80 8c [2] 8f 96 [2] 91 8b [2] 93 8a [2] 88 8c [2] 94 8b [2] 88 a4 }

  condition:
    any of them
}