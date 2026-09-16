rule TTP_XOR_QUAD_CurrentVersionRun_0a91 {
  strings:
    $key_0a91 = { 59 fe [2] 7d f0 [2] 56 dc [2] 78 fe [2] 6c e5 [2] 63 ff [2] 7d e2 [2] 7f e3 [2] 64 e5 [2] 78 e2 [2] 64 cd }

  condition:
    any of them
}