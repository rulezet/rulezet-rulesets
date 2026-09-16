rule TTP_XOR_QUAD_CurrentVersionRun_916d {
  strings:
    $key_916d = { c2 02 [2] e6 0c [2] cd 20 [2] e3 02 [2] f7 19 [2] f8 03 [2] e6 1e [2] e4 1f [2] ff 19 [2] e3 1e [2] ff 31 }

  condition:
    any of them
}