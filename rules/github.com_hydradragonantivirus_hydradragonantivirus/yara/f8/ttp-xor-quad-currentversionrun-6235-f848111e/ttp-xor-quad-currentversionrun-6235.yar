rule TTP_XOR_QUAD_CurrentVersionRun_6235 {
  strings:
    $key_6235 = { 31 5a [2] 15 54 [2] 3e 78 [2] 10 5a [2] 04 41 [2] 0b 5b [2] 15 46 [2] 17 47 [2] 0c 41 [2] 10 46 [2] 0c 69 }

  condition:
    any of them
}