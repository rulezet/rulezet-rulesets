rule TTP_XOR_QUAD_CurrentVersionRun_a311 {
  strings:
    $key_a311 = { f0 7e [2] d4 70 [2] ff 5c [2] d1 7e [2] c5 65 [2] ca 7f [2] d4 62 [2] d6 63 [2] cd 65 [2] d1 62 [2] cd 4d }

  condition:
    any of them
}