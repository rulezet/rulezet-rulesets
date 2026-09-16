rule TTP_XOR_QUAD_CurrentVersionRun_9284 {
  strings:
    $key_9284 = { c1 eb [2] e5 e5 [2] ce c9 [2] e0 eb [2] f4 f0 [2] fb ea [2] e5 f7 [2] e7 f6 [2] fc f0 [2] e0 f7 [2] fc d8 }

  condition:
    any of them
}