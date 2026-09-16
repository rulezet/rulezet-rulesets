rule TTP_XOR_QUAD_CurrentVersionRun_ff35 {
  strings:
    $key_ff35 = { ac 5a [2] 88 54 [2] a3 78 [2] 8d 5a [2] 99 41 [2] 96 5b [2] 88 46 [2] 8a 47 [2] 91 41 [2] 8d 46 [2] 91 69 }

  condition:
    any of them
}