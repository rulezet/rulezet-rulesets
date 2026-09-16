rule TTP_XOR_QUAD_CurrentVersionRun_6c4a {
  strings:
    $key_6c4a = { 3f 25 [2] 1b 2b [2] 30 07 [2] 1e 25 [2] 0a 3e [2] 05 24 [2] 1b 39 [2] 19 38 [2] 02 3e [2] 1e 39 [2] 02 16 }

  condition:
    any of them
}