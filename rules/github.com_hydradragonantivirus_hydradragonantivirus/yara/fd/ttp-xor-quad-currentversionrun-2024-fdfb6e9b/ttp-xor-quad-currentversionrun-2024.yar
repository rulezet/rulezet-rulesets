rule TTP_XOR_QUAD_CurrentVersionRun_2024 {
  strings:
    $key_2024 = { 73 4b [2] 57 45 [2] 7c 69 [2] 52 4b [2] 46 50 [2] 49 4a [2] 57 57 [2] 55 56 [2] 4e 50 [2] 52 57 [2] 4e 78 }

  condition:
    any of them
}