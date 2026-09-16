rule TTP_XOR_QUAD_CurrentVersionRun_914c {
  strings:
    $key_914c = { c2 23 [2] e6 2d [2] cd 01 [2] e3 23 [2] f7 38 [2] f8 22 [2] e6 3f [2] e4 3e [2] ff 38 [2] e3 3f [2] ff 10 }

  condition:
    any of them
}