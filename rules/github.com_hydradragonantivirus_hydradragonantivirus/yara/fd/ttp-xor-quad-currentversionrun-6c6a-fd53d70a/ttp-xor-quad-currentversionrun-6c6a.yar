rule TTP_XOR_QUAD_CurrentVersionRun_6c6a {
  strings:
    $key_6c6a = { 3f 05 [2] 1b 0b [2] 30 27 [2] 1e 05 [2] 0a 1e [2] 05 04 [2] 1b 19 [2] 19 18 [2] 02 1e [2] 1e 19 [2] 02 36 }

  condition:
    any of them
}