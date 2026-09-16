rule TTP_XOR_QUAD_CurrentVersionRun_929d {
  strings:
    $key_929d = { c1 f2 [2] e5 fc [2] ce d0 [2] e0 f2 [2] f4 e9 [2] fb f3 [2] e5 ee [2] e7 ef [2] fc e9 [2] e0 ee [2] fc c1 }

  condition:
    any of them
}