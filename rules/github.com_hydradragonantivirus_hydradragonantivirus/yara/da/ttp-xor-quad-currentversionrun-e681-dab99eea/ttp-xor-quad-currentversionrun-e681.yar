rule TTP_XOR_QUAD_CurrentVersionRun_e681 {
  strings:
    $key_e681 = { b5 ee [2] 91 e0 [2] ba cc [2] 94 ee [2] 80 f5 [2] 8f ef [2] 91 f2 [2] 93 f3 [2] 88 f5 [2] 94 f2 [2] 88 dd }

  condition:
    any of them
}