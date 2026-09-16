rule TTP_XOR_QUAD_CurrentVersionRun_a35b {
  strings:
    $key_a35b = { f0 34 [2] d4 3a [2] ff 16 [2] d1 34 [2] c5 2f [2] ca 35 [2] d4 28 [2] d6 29 [2] cd 2f [2] d1 28 [2] cd 07 }

  condition:
    any of them
}