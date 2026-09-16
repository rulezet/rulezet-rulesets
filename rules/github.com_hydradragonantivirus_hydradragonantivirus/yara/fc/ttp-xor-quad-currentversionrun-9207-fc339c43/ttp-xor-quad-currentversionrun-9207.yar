rule TTP_XOR_QUAD_CurrentVersionRun_9207 {
  strings:
    $key_9207 = { c1 68 [2] e5 66 [2] ce 4a [2] e0 68 [2] f4 73 [2] fb 69 [2] e5 74 [2] e7 75 [2] fc 73 [2] e0 74 [2] fc 5b }

  condition:
    any of them
}