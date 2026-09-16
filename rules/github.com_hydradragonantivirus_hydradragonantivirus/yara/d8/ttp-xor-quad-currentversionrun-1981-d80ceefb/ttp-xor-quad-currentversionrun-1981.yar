rule TTP_XOR_QUAD_CurrentVersionRun_1981 {
  strings:
    $key_1981 = { 4a ee [2] 6e e0 [2] 45 cc [2] 6b ee [2] 7f f5 [2] 70 ef [2] 6e f2 [2] 6c f3 [2] 77 f5 [2] 6b f2 [2] 77 dd }

  condition:
    any of them
}