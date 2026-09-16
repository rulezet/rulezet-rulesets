rule TTP_XOR_QUAD_CurrentVersionRun_1829 {
  strings:
    $key_1829 = { 4b 46 [2] 6f 48 [2] 44 64 [2] 6a 46 [2] 7e 5d [2] 71 47 [2] 6f 5a [2] 6d 5b [2] 76 5d [2] 6a 5a [2] 76 75 }

  condition:
    any of them
}