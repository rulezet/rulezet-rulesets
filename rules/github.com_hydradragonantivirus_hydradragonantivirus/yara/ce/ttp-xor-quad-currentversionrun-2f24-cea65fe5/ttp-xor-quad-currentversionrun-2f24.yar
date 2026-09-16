rule TTP_XOR_QUAD_CurrentVersionRun_2f24 {
  strings:
    $key_2f24 = { 7c 4b [2] 58 45 [2] 73 69 [2] 5d 4b [2] 49 50 [2] 46 4a [2] 58 57 [2] 5a 56 [2] 41 50 [2] 5d 57 [2] 41 78 }

  condition:
    any of them
}