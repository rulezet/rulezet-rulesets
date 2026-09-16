rule TTP_XOR_QUAD_CurrentVersionRun_a3fd {
  strings:
    $key_a3fd = { f0 92 [2] d4 9c [2] ff b0 [2] d1 92 [2] c5 89 [2] ca 93 [2] d4 8e [2] d6 8f [2] cd 89 [2] d1 8e [2] cd a1 }

  condition:
    any of them
}