rule TTP_XOR_QUAD_CurrentVersionRun_6228 {
  strings:
    $key_6228 = { 31 47 [2] 15 49 [2] 3e 65 [2] 10 47 [2] 04 5c [2] 0b 46 [2] 15 5b [2] 17 5a [2] 0c 5c [2] 10 5b [2] 0c 74 }

  condition:
    any of them
}