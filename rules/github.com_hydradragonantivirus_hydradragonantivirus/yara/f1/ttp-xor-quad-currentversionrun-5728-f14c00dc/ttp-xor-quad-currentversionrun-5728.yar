rule TTP_XOR_QUAD_CurrentVersionRun_5728 {
  strings:
    $key_5728 = { 04 47 [2] 20 49 [2] 0b 65 [2] 25 47 [2] 31 5c [2] 3e 46 [2] 20 5b [2] 22 5a [2] 39 5c [2] 25 5b [2] 39 74 }

  condition:
    any of them
}