rule TTP_XOR_QUAD_CurrentVersionRun_ff72 {
  strings:
    $key_ff72 = { ac 1d [2] 88 13 [2] a3 3f [2] 8d 1d [2] 99 06 [2] 96 1c [2] 88 01 [2] 8a 00 [2] 91 06 [2] 8d 01 [2] 91 2e }

  condition:
    any of them
}