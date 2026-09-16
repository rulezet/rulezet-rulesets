rule TTP_XOR_QUAD_CurrentVersionRun_3707 {
  strings:
    $key_3707 = { 64 68 [2] 40 66 [2] 6b 4a [2] 45 68 [2] 51 73 [2] 5e 69 [2] 40 74 [2] 42 75 [2] 59 73 [2] 45 74 [2] 59 5b }

  condition:
    any of them
}