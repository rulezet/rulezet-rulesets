rule TTP_XOR_QUAD_CurrentVersionRun_6719 {
  strings:
    $key_6719 = { 34 76 [2] 10 78 [2] 3b 54 [2] 15 76 [2] 01 6d [2] 0e 77 [2] 10 6a [2] 12 6b [2] 09 6d [2] 15 6a [2] 09 45 }

  condition:
    any of them
}