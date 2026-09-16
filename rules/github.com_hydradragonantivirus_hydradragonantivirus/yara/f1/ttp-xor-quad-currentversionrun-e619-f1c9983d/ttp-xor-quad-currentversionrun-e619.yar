rule TTP_XOR_QUAD_CurrentVersionRun_e619 {
  strings:
    $key_e619 = { b5 76 [2] 91 78 [2] ba 54 [2] 94 76 [2] 80 6d [2] 8f 77 [2] 91 6a [2] 93 6b [2] 88 6d [2] 94 6a [2] 88 45 }

  condition:
    any of them
}