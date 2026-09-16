rule TTP_XOR_QUAD_CurrentVersionRun_a3c1 {
  strings:
    $key_a3c1 = { f0 ae [2] d4 a0 [2] ff 8c [2] d1 ae [2] c5 b5 [2] ca af [2] d4 b2 [2] d6 b3 [2] cd b5 [2] d1 b2 [2] cd 9d }

  condition:
    any of them
}