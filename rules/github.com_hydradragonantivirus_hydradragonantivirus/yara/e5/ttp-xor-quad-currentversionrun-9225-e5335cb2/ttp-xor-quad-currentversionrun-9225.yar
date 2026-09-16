rule TTP_XOR_QUAD_CurrentVersionRun_9225 {
  strings:
    $key_9225 = { c1 4a [2] e5 44 [2] ce 68 [2] e0 4a [2] f4 51 [2] fb 4b [2] e5 56 [2] e7 57 [2] fc 51 [2] e0 56 [2] fc 79 }

  condition:
    any of them
}