rule TTP_XOR_QUAD_CurrentVersionRun_a5f2 {
  strings:
    $key_a5f2 = { f6 9d [2] d2 93 [2] f9 bf [2] d7 9d [2] c3 86 [2] cc 9c [2] d2 81 [2] d0 80 [2] cb 86 [2] d7 81 [2] cb ae }

  condition:
    any of them
}