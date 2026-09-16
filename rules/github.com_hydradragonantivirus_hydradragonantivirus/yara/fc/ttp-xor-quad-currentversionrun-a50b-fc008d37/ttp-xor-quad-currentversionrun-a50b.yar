rule TTP_XOR_QUAD_CurrentVersionRun_a50b {
  strings:
    $key_a50b = { f6 64 [2] d2 6a [2] f9 46 [2] d7 64 [2] c3 7f [2] cc 65 [2] d2 78 [2] d0 79 [2] cb 7f [2] d7 78 [2] cb 57 }

  condition:
    any of them
}