rule TTP_XOR_QUAD_CurrentVersionRun_ff78 {
  strings:
    $key_ff78 = { ac 17 [2] 88 19 [2] a3 35 [2] 8d 17 [2] 99 0c [2] 96 16 [2] 88 0b [2] 8a 0a [2] 91 0c [2] 8d 0b [2] 91 24 }

  condition:
    any of them
}