rule TTP_XOR_QUAD_CurrentVersionRun_726b {
  strings:
    $key_726b = { 21 04 [2] 05 0a [2] 2e 26 [2] 00 04 [2] 14 1f [2] 1b 05 [2] 05 18 [2] 07 19 [2] 1c 1f [2] 00 18 [2] 1c 37 }

  condition:
    any of them
}