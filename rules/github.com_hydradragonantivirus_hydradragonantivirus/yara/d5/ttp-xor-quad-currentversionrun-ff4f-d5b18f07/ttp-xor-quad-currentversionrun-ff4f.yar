rule TTP_XOR_QUAD_CurrentVersionRun_ff4f {
  strings:
    $key_ff4f = { ac 20 [2] 88 2e [2] a3 02 [2] 8d 20 [2] 99 3b [2] 96 21 [2] 88 3c [2] 8a 3d [2] 91 3b [2] 8d 3c [2] 91 13 }

  condition:
    any of them
}