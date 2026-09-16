rule TTP_XOR_QUAD_CurrentVersionRun_911c {
  strings:
    $key_911c = { c2 73 [2] e6 7d [2] cd 51 [2] e3 73 [2] f7 68 [2] f8 72 [2] e6 6f [2] e4 6e [2] ff 68 [2] e3 6f [2] ff 40 }

  condition:
    any of them
}