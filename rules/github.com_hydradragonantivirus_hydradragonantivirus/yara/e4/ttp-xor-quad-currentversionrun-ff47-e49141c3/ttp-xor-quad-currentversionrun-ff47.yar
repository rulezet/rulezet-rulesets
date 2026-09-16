rule TTP_XOR_QUAD_CurrentVersionRun_ff47 {
  strings:
    $key_ff47 = { ac 28 [2] 88 26 [2] a3 0a [2] 8d 28 [2] 99 33 [2] 96 29 [2] 88 34 [2] 8a 35 [2] 91 33 [2] 8d 34 [2] 91 1b }

  condition:
    any of them
}