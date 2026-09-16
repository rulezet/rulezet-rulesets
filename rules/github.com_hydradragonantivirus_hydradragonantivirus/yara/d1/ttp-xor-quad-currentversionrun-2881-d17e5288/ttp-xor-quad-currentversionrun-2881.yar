rule TTP_XOR_QUAD_CurrentVersionRun_2881 {
  strings:
    $key_2881 = { 7b ee [2] 5f e0 [2] 74 cc [2] 5a ee [2] 4e f5 [2] 41 ef [2] 5f f2 [2] 5d f3 [2] 46 f5 [2] 5a f2 [2] 46 dd }

  condition:
    any of them
}