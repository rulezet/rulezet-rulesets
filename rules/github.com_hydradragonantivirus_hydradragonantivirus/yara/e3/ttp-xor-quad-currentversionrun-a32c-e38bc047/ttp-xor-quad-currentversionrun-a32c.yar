rule TTP_XOR_QUAD_CurrentVersionRun_a32c {
  strings:
    $key_a32c = { f0 43 [2] d4 4d [2] ff 61 [2] d1 43 [2] c5 58 [2] ca 42 [2] d4 5f [2] d6 5e [2] cd 58 [2] d1 5f [2] cd 70 }

  condition:
    any of them
}