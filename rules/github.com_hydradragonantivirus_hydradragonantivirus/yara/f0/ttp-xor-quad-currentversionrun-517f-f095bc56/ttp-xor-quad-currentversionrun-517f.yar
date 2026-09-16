rule TTP_XOR_QUAD_CurrentVersionRun_517f {
  strings:
    $key_517f = { 02 10 [2] 26 1e [2] 0d 32 [2] 23 10 [2] 37 0b [2] 38 11 [2] 26 0c [2] 24 0d [2] 3f 0b [2] 23 0c [2] 3f 23 }

  condition:
    any of them
}