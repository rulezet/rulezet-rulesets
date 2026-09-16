rule TTP_XOR_QUAD_CurrentVersionRun_91e3 {
  strings:
    $key_91e3 = { c2 8c [2] e6 82 [2] cd ae [2] e3 8c [2] f7 97 [2] f8 8d [2] e6 90 [2] e4 91 [2] ff 97 [2] e3 90 [2] ff bf }

  condition:
    any of them
}