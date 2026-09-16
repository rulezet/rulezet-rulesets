rule TTP_XOR_QUAD_CurrentVersionRun_2e28 {
  strings:
    $key_2e28 = { 7d 47 [2] 59 49 [2] 72 65 [2] 5c 47 [2] 48 5c [2] 47 46 [2] 59 5b [2] 5b 5a [2] 40 5c [2] 5c 5b [2] 40 74 }

  condition:
    any of them
}