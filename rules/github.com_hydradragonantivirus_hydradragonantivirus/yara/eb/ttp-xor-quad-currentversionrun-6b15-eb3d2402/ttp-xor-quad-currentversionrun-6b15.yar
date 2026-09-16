rule TTP_XOR_QUAD_CurrentVersionRun_6b15 {
  strings:
    $key_6b15 = { 38 7a [2] 1c 74 [2] 37 58 [2] 19 7a [2] 0d 61 [2] 02 7b [2] 1c 66 [2] 1e 67 [2] 05 61 [2] 19 66 [2] 05 49 }

  condition:
    any of them
}