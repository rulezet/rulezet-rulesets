rule TTP_XOR_QUAD_CurrentVersionRun_ff31 {
  strings:
    $key_ff31 = { ac 5e [2] 88 50 [2] a3 7c [2] 8d 5e [2] 99 45 [2] 96 5f [2] 88 42 [2] 8a 43 [2] 91 45 [2] 8d 42 [2] 91 6d }

  condition:
    any of them
}