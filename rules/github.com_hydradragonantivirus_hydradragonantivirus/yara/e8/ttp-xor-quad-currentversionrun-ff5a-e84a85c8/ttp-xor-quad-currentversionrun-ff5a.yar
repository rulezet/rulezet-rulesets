rule TTP_XOR_QUAD_CurrentVersionRun_ff5a {
  strings:
    $key_ff5a = { ac 35 [2] 88 3b [2] a3 17 [2] 8d 35 [2] 99 2e [2] 96 34 [2] 88 29 [2] 8a 28 [2] 91 2e [2] 8d 29 [2] 91 06 }

  condition:
    any of them
}