rule TTP_XOR_QUAD_CurrentVersionRun_9281 {
  strings:
    $key_9281 = { c1 ee [2] e5 e0 [2] ce cc [2] e0 ee [2] f4 f5 [2] fb ef [2] e5 f2 [2] e7 f3 [2] fc f5 [2] e0 f2 [2] fc dd }

  condition:
    any of them
}