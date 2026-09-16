rule TTP_XOR_QUAD_CurrentVersionRun_1a91 {
  strings:
    $key_1a91 = { 49 fe [2] 6d f0 [2] 46 dc [2] 68 fe [2] 7c e5 [2] 73 ff [2] 6d e2 [2] 6f e3 [2] 74 e5 [2] 68 e2 [2] 74 cd }

  condition:
    any of them
}