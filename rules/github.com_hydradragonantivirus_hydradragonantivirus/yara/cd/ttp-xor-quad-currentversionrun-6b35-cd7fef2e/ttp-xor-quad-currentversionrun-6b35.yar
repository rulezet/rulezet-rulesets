rule TTP_XOR_QUAD_CurrentVersionRun_6b35 {
  strings:
    $key_6b35 = { 38 5a [2] 1c 54 [2] 37 78 [2] 19 5a [2] 0d 41 [2] 02 5b [2] 1c 46 [2] 1e 47 [2] 05 41 [2] 19 46 [2] 05 69 }

  condition:
    any of them
}