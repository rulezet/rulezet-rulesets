rule TTP_XOR_QUAD_CurrentVersionRun_ff4b {
  strings:
    $key_ff4b = { ac 24 [2] 88 2a [2] a3 06 [2] 8d 24 [2] 99 3f [2] 96 25 [2] 88 38 [2] 8a 39 [2] 91 3f [2] 8d 38 [2] 91 17 }

  condition:
    any of them
}