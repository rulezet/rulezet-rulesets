rule TTP_XOR_QUAD_CurrentVersionRun_9a91 {
  strings:
    $key_9a91 = { c9 fe [2] ed f0 [2] c6 dc [2] e8 fe [2] fc e5 [2] f3 ff [2] ed e2 [2] ef e3 [2] f4 e5 [2] e8 e2 [2] f4 cd }

  condition:
    any of them
}