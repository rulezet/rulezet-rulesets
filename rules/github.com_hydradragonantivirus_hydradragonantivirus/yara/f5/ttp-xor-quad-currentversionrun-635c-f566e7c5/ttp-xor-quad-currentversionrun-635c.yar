rule TTP_XOR_QUAD_CurrentVersionRun_635c {
  strings:
    $key_635c = { 30 33 [2] 14 3d [2] 3f 11 [2] 11 33 [2] 05 28 [2] 0a 32 [2] 14 2f [2] 16 2e [2] 0d 28 [2] 11 2f [2] 0d 00 }

  condition:
    any of them
}