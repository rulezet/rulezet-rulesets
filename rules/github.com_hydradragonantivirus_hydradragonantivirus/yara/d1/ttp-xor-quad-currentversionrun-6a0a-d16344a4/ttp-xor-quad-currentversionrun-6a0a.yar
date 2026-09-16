rule TTP_XOR_QUAD_CurrentVersionRun_6a0a {
  strings:
    $key_6a0a = { 39 65 [2] 1d 6b [2] 36 47 [2] 18 65 [2] 0c 7e [2] 03 64 [2] 1d 79 [2] 1f 78 [2] 04 7e [2] 18 79 [2] 04 56 }

  condition:
    any of them
}