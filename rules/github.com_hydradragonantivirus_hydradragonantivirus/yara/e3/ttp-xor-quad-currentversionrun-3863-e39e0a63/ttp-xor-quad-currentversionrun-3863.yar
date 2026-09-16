rule TTP_XOR_QUAD_CurrentVersionRun_3863 {
  strings:
    $key_3863 = { 6b 0c [2] 4f 02 [2] 64 2e [2] 4a 0c [2] 5e 17 [2] 51 0d [2] 4f 10 [2] 4d 11 [2] 56 17 [2] 4a 10 [2] 56 3f }

  condition:
    any of them
}