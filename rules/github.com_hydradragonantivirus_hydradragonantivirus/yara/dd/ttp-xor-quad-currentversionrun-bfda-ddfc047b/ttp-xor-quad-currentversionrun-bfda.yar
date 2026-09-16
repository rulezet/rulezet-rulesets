rule TTP_XOR_QUAD_CurrentVersionRun_bfda {
  strings:
    $key_bfda = { ec b5 [2] c8 bb [2] e3 97 [2] cd b5 [2] d9 ae [2] d6 b4 [2] c8 a9 [2] ca a8 [2] d1 ae [2] cd a9 [2] d1 86 }

  condition:
    any of them
}