rule TTP_XOR_QUAD_CurrentVersionRun_206a {
  strings:
    $key_206a = { 73 05 [2] 57 0b [2] 7c 27 [2] 52 05 [2] 46 1e [2] 49 04 [2] 57 19 [2] 55 18 [2] 4e 1e [2] 52 19 [2] 4e 36 }

  condition:
    any of them
}