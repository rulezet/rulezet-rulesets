rule TTP_XOR_QUAD_CurrentVersionRun_ff71 {
  strings:
    $key_ff71 = { ac 1e [2] 88 10 [2] a3 3c [2] 8d 1e [2] 99 05 [2] 96 1f [2] 88 02 [2] 8a 03 [2] 91 05 [2] 8d 02 [2] 91 2d }

  condition:
    any of them
}