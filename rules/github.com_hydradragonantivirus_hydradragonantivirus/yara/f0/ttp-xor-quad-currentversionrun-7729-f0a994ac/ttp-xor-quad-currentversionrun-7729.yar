rule TTP_XOR_QUAD_CurrentVersionRun_7729 {
  strings:
    $key_7729 = { 24 46 [2] 00 48 [2] 2b 64 [2] 05 46 [2] 11 5d [2] 1e 47 [2] 00 5a [2] 02 5b [2] 19 5d [2] 05 5a [2] 19 75 }

  condition:
    any of them
}