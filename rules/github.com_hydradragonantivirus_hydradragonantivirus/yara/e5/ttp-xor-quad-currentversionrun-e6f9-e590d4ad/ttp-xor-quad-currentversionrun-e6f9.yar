rule TTP_XOR_QUAD_CurrentVersionRun_e6f9 {
  strings:
    $key_e6f9 = { b5 96 [2] 91 98 [2] ba b4 [2] 94 96 [2] 80 8d [2] 8f 97 [2] 91 8a [2] 93 8b [2] 88 8d [2] 94 8a [2] 88 a5 }

  condition:
    any of them
}