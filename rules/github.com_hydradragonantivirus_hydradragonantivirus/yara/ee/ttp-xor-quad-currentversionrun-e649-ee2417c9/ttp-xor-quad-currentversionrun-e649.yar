rule TTP_XOR_QUAD_CurrentVersionRun_e649 {
  strings:
    $key_e649 = { b5 26 [2] 91 28 [2] ba 04 [2] 94 26 [2] 80 3d [2] 8f 27 [2] 91 3a [2] 93 3b [2] 88 3d [2] 94 3a [2] 88 15 }

  condition:
    any of them
}