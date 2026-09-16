rule TTP_XOR_QUAD_CurrentVersionRun_4b28 {
  strings:
    $key_4b28 = { 18 47 [2] 3c 49 [2] 17 65 [2] 39 47 [2] 2d 5c [2] 22 46 [2] 3c 5b [2] 3e 5a [2] 25 5c [2] 39 5b [2] 25 74 }

  condition:
    any of them
}