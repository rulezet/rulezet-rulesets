rule TTP_XOR_QUAD_CurrentVersionRun_920f {
  strings:
    $key_920f = { c1 60 [2] e5 6e [2] ce 42 [2] e0 60 [2] f4 7b [2] fb 61 [2] e5 7c [2] e7 7d [2] fc 7b [2] e0 7c [2] fc 53 }

  condition:
    any of them
}