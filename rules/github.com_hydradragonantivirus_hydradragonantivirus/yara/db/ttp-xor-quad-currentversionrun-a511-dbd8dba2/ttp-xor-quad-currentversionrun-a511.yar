rule TTP_XOR_QUAD_CurrentVersionRun_a511 {
  strings:
    $key_a511 = { f6 7e [2] d2 70 [2] f9 5c [2] d7 7e [2] c3 65 [2] cc 7f [2] d2 62 [2] d0 63 [2] cb 65 [2] d7 62 [2] cb 4d }

  condition:
    any of them
}