rule TTP_XOR_QUAD_CurrentVersionRun_ed81 {
  strings:
    $key_ed81 = { be ee [2] 9a e0 [2] b1 cc [2] 9f ee [2] 8b f5 [2] 84 ef [2] 9a f2 [2] 98 f3 [2] 83 f5 [2] 9f f2 [2] 83 dd }

  condition:
    any of them
}