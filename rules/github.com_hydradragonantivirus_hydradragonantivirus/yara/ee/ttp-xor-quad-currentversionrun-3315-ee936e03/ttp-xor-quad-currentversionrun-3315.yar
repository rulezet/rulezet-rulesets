rule TTP_XOR_QUAD_CurrentVersionRun_3315 {
  strings:
    $key_3315 = { 60 7a [2] 44 74 [2] 6f 58 [2] 41 7a [2] 55 61 [2] 5a 7b [2] 44 66 [2] 46 67 [2] 5d 61 [2] 41 66 [2] 5d 49 }

  condition:
    any of them
}