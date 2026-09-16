rule TTP_XOR_QUAD_CurrentVersionRun_61dd {
  strings:
    $key_61dd = { 32 b2 [2] 16 bc [2] 3d 90 [2] 13 b2 [2] 07 a9 [2] 08 b3 [2] 16 ae [2] 14 af [2] 0f a9 [2] 13 ae [2] 0f 81 }

  condition:
    any of them
}