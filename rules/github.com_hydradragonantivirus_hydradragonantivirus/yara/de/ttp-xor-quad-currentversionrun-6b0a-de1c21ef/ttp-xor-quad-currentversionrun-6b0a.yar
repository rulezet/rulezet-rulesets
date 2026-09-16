rule TTP_XOR_QUAD_CurrentVersionRun_6b0a {
  strings:
    $key_6b0a = { 38 65 [2] 1c 6b [2] 37 47 [2] 19 65 [2] 0d 7e [2] 02 64 [2] 1c 79 [2] 1e 78 [2] 05 7e [2] 19 79 [2] 05 56 }

  condition:
    any of them
}