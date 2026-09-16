rule TTP_XOR_QUAD_CurrentVersionRun_ff13 {
  strings:
    $key_ff13 = { ac 7c [2] 88 72 [2] a3 5e [2] 8d 7c [2] 99 67 [2] 96 7d [2] 88 60 [2] 8a 61 [2] 91 67 [2] 8d 60 [2] 91 4f }

  condition:
    any of them
}