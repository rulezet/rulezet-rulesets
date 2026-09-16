rule TTP_XOR_QUAD_CurrentVersionRun_913e {
  strings:
    $key_913e = { c2 51 [2] e6 5f [2] cd 73 [2] e3 51 [2] f7 4a [2] f8 50 [2] e6 4d [2] e4 4c [2] ff 4a [2] e3 4d [2] ff 62 }

  condition:
    any of them
}