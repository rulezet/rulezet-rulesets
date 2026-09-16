rule TTP_XOR_QUAD_CurrentVersionRun_9229 {
  strings:
    $key_9229 = { c1 46 [2] e5 48 [2] ce 64 [2] e0 46 [2] f4 5d [2] fb 47 [2] e5 5a [2] e7 5b [2] fc 5d [2] e0 5a [2] fc 75 }

  condition:
    any of them
}