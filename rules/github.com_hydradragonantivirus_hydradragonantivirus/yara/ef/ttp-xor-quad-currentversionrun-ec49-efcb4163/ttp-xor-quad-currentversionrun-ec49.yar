rule TTP_XOR_QUAD_CurrentVersionRun_ec49 {
  strings:
    $key_ec49 = { bf 26 [2] 9b 28 [2] b0 04 [2] 9e 26 [2] 8a 3d [2] 85 27 [2] 9b 3a [2] 99 3b [2] 82 3d [2] 9e 3a [2] 82 15 }

  condition:
    any of them
}