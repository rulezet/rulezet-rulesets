rule TTP_XOR_QUAD_CurrentVersionRun_ff38 {
  strings:
    $key_ff38 = { ac 57 [2] 88 59 [2] a3 75 [2] 8d 57 [2] 99 4c [2] 96 56 [2] 88 4b [2] 8a 4a [2] 91 4c [2] 8d 4b [2] 91 64 }

  condition:
    any of them
}