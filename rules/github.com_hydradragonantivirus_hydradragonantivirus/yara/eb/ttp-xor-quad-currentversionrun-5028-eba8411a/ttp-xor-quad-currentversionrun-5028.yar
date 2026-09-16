rule TTP_XOR_QUAD_CurrentVersionRun_5028 {
  strings:
    $key_5028 = { 03 47 [2] 27 49 [2] 0c 65 [2] 22 47 [2] 36 5c [2] 39 46 [2] 27 5b [2] 25 5a [2] 3e 5c [2] 22 5b [2] 3e 74 }

  condition:
    any of them
}