rule TTP_XOR_QUAD_CurrentVersionRun_a391 {
  strings:
    $key_a391 = { f0 fe [2] d4 f0 [2] ff dc [2] d1 fe [2] c5 e5 [2] ca ff [2] d4 e2 [2] d6 e3 [2] cd e5 [2] d1 e2 [2] cd cd }

  condition:
    any of them
}