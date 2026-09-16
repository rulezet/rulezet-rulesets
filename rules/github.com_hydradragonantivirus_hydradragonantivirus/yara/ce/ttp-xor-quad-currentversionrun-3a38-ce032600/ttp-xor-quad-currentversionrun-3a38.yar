rule TTP_XOR_QUAD_CurrentVersionRun_3a38 {
  strings:
    $key_3a38 = { 69 57 [2] 4d 59 [2] 66 75 [2] 48 57 [2] 5c 4c [2] 53 56 [2] 4d 4b [2] 4f 4a [2] 54 4c [2] 48 4b [2] 54 64 }

  condition:
    any of them
}