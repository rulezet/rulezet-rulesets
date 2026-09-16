rule TTP_XOR_QUAD_CurrentVersionRun_61ad {
  strings:
    $key_61ad = { 32 c2 [2] 16 cc [2] 3d e0 [2] 13 c2 [2] 07 d9 [2] 08 c3 [2] 16 de [2] 14 df [2] 0f d9 [2] 13 de [2] 0f f1 }

  condition:
    any of them
}