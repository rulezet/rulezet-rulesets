rule TTP_XOR_QUAD_CurrentVersionRun_a533 {
  strings:
    $key_a533 = { f6 5c [2] d2 52 [2] f9 7e [2] d7 5c [2] c3 47 [2] cc 5d [2] d2 40 [2] d0 41 [2] cb 47 [2] d7 40 [2] cb 6f }

  condition:
    any of them
}