rule TTP_XOR_QUAD_CurrentVersionRun_510a {
  strings:
    $key_510a = { 02 65 [2] 26 6b [2] 0d 47 [2] 23 65 [2] 37 7e [2] 38 64 [2] 26 79 [2] 24 78 [2] 3f 7e [2] 23 79 [2] 3f 56 }

  condition:
    any of them
}