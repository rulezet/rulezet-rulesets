rule TTP_XOR_QUAD_CurrentVersionRun_ff33 {
  strings:
    $key_ff33 = { ac 5c [2] 88 52 [2] a3 7e [2] 8d 5c [2] 99 47 [2] 96 5d [2] 88 40 [2] 8a 41 [2] 91 47 [2] 8d 40 [2] 91 6f }

  condition:
    any of them
}