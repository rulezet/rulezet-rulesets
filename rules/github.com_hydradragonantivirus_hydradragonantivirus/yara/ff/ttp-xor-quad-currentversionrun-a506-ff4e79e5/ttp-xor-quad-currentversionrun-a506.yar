rule TTP_XOR_QUAD_CurrentVersionRun_a506 {
  strings:
    $key_a506 = { f6 69 [2] d2 67 [2] f9 4b [2] d7 69 [2] c3 72 [2] cc 68 [2] d2 75 [2] d0 74 [2] cb 72 [2] d7 75 [2] cb 5a }

  condition:
    any of them
}