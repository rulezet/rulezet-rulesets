rule TTP_XOR_QUAD_CurrentVersionRun_91e5 {
  strings:
    $key_91e5 = { c2 8a [2] e6 84 [2] cd a8 [2] e3 8a [2] f7 91 [2] f8 8b [2] e6 96 [2] e4 97 [2] ff 91 [2] e3 96 [2] ff b9 }

  condition:
    any of them
}