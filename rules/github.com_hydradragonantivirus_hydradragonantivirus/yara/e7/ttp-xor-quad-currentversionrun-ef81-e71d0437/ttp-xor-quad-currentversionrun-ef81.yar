rule TTP_XOR_QUAD_CurrentVersionRun_ef81 {
  strings:
    $key_ef81 = { bc ee [2] 98 e0 [2] b3 cc [2] 9d ee [2] 89 f5 [2] 86 ef [2] 98 f2 [2] 9a f3 [2] 81 f5 [2] 9d f2 [2] 81 dd }

  condition:
    any of them
}