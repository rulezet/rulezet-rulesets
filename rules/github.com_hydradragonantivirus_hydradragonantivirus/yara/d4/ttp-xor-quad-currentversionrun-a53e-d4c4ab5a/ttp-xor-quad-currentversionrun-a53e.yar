rule TTP_XOR_QUAD_CurrentVersionRun_a53e {
  strings:
    $key_a53e = { f6 51 [2] d2 5f [2] f9 73 [2] d7 51 [2] c3 4a [2] cc 50 [2] d2 4d [2] d0 4c [2] cb 4a [2] d7 4d [2] cb 62 }

  condition:
    any of them
}