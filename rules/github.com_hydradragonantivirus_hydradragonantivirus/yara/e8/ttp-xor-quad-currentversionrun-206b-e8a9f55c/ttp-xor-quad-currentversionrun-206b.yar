rule TTP_XOR_QUAD_CurrentVersionRun_206b {
  strings:
    $key_206b = { 73 04 [2] 57 0a [2] 7c 26 [2] 52 04 [2] 46 1f [2] 49 05 [2] 57 18 [2] 55 19 [2] 4e 1f [2] 52 18 [2] 4e 37 }

  condition:
    any of them
}