rule TTP_XOR_QUAD_CurrentVersionRun_917f {
  strings:
    $key_917f = { c2 10 [2] e6 1e [2] cd 32 [2] e3 10 [2] f7 0b [2] f8 11 [2] e6 0c [2] e4 0d [2] ff 0b [2] e3 0c [2] ff 23 }

  condition:
    any of them
}