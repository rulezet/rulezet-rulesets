rule TTP_XOR_QUAD_CurrentVersionRun_a53c {
  strings:
    $key_a53c = { f6 53 [2] d2 5d [2] f9 71 [2] d7 53 [2] c3 48 [2] cc 52 [2] d2 4f [2] d0 4e [2] cb 48 [2] d7 4f [2] cb 60 }

  condition:
    any of them
}