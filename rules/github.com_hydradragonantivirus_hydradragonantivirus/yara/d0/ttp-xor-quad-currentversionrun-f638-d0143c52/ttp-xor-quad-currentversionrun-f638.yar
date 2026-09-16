rule TTP_XOR_QUAD_CurrentVersionRun_f638 {
  strings:
    $key_f638 = { a5 57 [2] 81 59 [2] aa 75 [2] 84 57 [2] 90 4c [2] 9f 56 [2] 81 4b [2] 83 4a [2] 98 4c [2] 84 4b [2] 98 64 }

  condition:
    any of them
}