rule TTP_XOR_QUAD_CurrentVersionRun_e665 {
  strings:
    $key_e665 = { b5 0a [2] 91 04 [2] ba 28 [2] 94 0a [2] 80 11 [2] 8f 0b [2] 91 16 [2] 93 17 [2] 88 11 [2] 94 16 [2] 88 39 }

  condition:
    any of them
}