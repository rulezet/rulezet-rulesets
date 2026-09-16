rule TTP_XOR_QUAD_CurrentVersionRun_ff2d {
  strings:
    $key_ff2d = { ac 42 [2] 88 4c [2] a3 60 [2] 8d 42 [2] 99 59 [2] 96 43 [2] 88 5e [2] 8a 5f [2] 91 59 [2] 8d 5e [2] 91 71 }

  condition:
    any of them
}