rule TTP_XOR_QUAD_CurrentVersionRun_5781 {
  strings:
    $key_5781 = { 04 ee [2] 20 e0 [2] 0b cc [2] 25 ee [2] 31 f5 [2] 3e ef [2] 20 f2 [2] 22 f3 [2] 39 f5 [2] 25 f2 [2] 39 dd }

  condition:
    any of them
}