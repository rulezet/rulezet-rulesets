rule TTP_XOR_QUAD_CurrentVersionRun_5078 {
  strings:
    $key_5078 = { 03 17 [2] 27 19 [2] 0c 35 [2] 22 17 [2] 36 0c [2] 39 16 [2] 27 0b [2] 25 0a [2] 3e 0c [2] 22 0b [2] 3e 24 }

  condition:
    any of them
}