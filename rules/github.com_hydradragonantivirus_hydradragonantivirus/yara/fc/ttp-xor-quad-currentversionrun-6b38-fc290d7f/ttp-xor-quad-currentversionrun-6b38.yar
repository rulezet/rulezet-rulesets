rule TTP_XOR_QUAD_CurrentVersionRun_6b38 {
  strings:
    $key_6b38 = { 38 57 [2] 1c 59 [2] 37 75 [2] 19 57 [2] 0d 4c [2] 02 56 [2] 1c 4b [2] 1e 4a [2] 05 4c [2] 19 4b [2] 05 64 }

  condition:
    any of them
}