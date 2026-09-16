rule TTP_XOR_QUAD_CurrentVersionRun_e60b {
  strings:
    $key_e60b = { b5 64 [2] 91 6a [2] ba 46 [2] 94 64 [2] 80 7f [2] 8f 65 [2] 91 78 [2] 93 79 [2] 88 7f [2] 94 78 [2] 88 57 }

  condition:
    any of them
}