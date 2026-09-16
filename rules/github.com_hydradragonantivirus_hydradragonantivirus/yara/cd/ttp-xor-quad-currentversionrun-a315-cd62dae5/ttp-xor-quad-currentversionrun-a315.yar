rule TTP_XOR_QUAD_CurrentVersionRun_a315 {
  strings:
    $key_a315 = { f0 7a [2] d4 74 [2] ff 58 [2] d1 7a [2] c5 61 [2] ca 7b [2] d4 66 [2] d6 67 [2] cd 61 [2] d1 66 [2] cd 49 }

  condition:
    any of them
}