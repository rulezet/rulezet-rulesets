rule TTP_XOR_QUAD_CurrentVersionRun_3a35 {
  strings:
    $key_3a35 = { 69 5a [2] 4d 54 [2] 66 78 [2] 48 5a [2] 5c 41 [2] 53 5b [2] 4d 46 [2] 4f 47 [2] 54 41 [2] 48 46 [2] 54 69 }

  condition:
    any of them
}