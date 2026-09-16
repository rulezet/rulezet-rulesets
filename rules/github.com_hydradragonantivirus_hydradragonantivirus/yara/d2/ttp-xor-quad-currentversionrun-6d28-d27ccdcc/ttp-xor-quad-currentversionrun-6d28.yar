rule TTP_XOR_QUAD_CurrentVersionRun_6d28 {
  strings:
    $key_6d28 = { 3e 47 [2] 1a 49 [2] 31 65 [2] 1f 47 [2] 0b 5c [2] 04 46 [2] 1a 5b [2] 18 5a [2] 03 5c [2] 1f 5b [2] 03 74 }

  condition:
    any of them
}