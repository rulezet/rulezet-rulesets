rule TTP_XOR_QUAD_CurrentVersionRun_bfdc {
  strings:
    $key_bfdc = { ec b3 [2] c8 bd [2] e3 91 [2] cd b3 [2] d9 a8 [2] d6 b2 [2] c8 af [2] ca ae [2] d1 a8 [2] cd af [2] d1 80 }

  condition:
    any of them
}