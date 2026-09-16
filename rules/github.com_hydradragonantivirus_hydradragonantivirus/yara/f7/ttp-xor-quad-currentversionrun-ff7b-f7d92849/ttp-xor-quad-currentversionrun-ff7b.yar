rule TTP_XOR_QUAD_CurrentVersionRun_ff7b {
  strings:
    $key_ff7b = { ac 14 [2] 88 1a [2] a3 36 [2] 8d 14 [2] 99 0f [2] 96 15 [2] 88 08 [2] 8a 09 [2] 91 0f [2] 8d 08 [2] 91 27 }

  condition:
    any of them
}