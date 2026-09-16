rule TTP_XOR_QUAD_CurrentVersionRun_ff14 {
  strings:
    $key_ff14 = { ac 7b [2] 88 75 [2] a3 59 [2] 8d 7b [2] 99 60 [2] 96 7a [2] 88 67 [2] 8a 66 [2] 91 60 [2] 8d 67 [2] 91 48 }

  condition:
    any of them
}