rule TTP_XOR_QUAD_CurrentVersionRun_91eb {
  strings:
    $key_91eb = { c2 84 [2] e6 8a [2] cd a6 [2] e3 84 [2] f7 9f [2] f8 85 [2] e6 98 [2] e4 99 [2] ff 9f [2] e3 98 [2] ff b7 }

  condition:
    any of them
}