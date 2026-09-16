rule TTP_XOR_QUAD_CurrentVersionRun_920d {
  strings:
    $key_920d = { c1 62 [2] e5 6c [2] ce 40 [2] e0 62 [2] f4 79 [2] fb 63 [2] e5 7e [2] e7 7f [2] fc 79 [2] e0 7e [2] fc 51 }

  condition:
    any of them
}