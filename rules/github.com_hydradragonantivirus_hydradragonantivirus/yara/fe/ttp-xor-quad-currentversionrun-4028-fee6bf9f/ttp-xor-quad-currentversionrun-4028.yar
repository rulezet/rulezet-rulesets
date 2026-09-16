rule TTP_XOR_QUAD_CurrentVersionRun_4028 {
  strings:
    $key_4028 = { 13 47 [2] 37 49 [2] 1c 65 [2] 32 47 [2] 26 5c [2] 29 46 [2] 37 5b [2] 35 5a [2] 2e 5c [2] 32 5b [2] 2e 74 }

  condition:
    any of them
}