rule TTP_XOR_QUAD_CurrentVersionRun_ff1e {
  strings:
    $key_ff1e = { ac 71 [2] 88 7f [2] a3 53 [2] 8d 71 [2] 99 6a [2] 96 70 [2] 88 6d [2] 8a 6c [2] 91 6a [2] 8d 6d [2] 91 42 }

  condition:
    any of them
}