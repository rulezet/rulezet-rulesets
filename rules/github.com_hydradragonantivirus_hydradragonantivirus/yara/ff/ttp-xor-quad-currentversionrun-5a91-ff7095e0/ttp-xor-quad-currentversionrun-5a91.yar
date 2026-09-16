rule TTP_XOR_QUAD_CurrentVersionRun_5a91 {
  strings:
    $key_5a91 = { 09 fe [2] 2d f0 [2] 06 dc [2] 28 fe [2] 3c e5 [2] 33 ff [2] 2d e2 [2] 2f e3 [2] 34 e5 [2] 28 e2 [2] 34 cd }

  condition:
    any of them
}