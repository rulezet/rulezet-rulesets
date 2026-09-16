rule TTP_XOR_QUAD_CurrentVersionRun_3a91 {
  strings:
    $key_3a91 = { 69 fe [2] 4d f0 [2] 66 dc [2] 48 fe [2] 5c e5 [2] 53 ff [2] 4d e2 [2] 4f e3 [2] 54 e5 [2] 48 e2 [2] 54 cd }

  condition:
    any of them
}