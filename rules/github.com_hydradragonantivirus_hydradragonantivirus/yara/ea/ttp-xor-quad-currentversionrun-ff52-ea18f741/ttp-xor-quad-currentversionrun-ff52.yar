rule TTP_XOR_QUAD_CurrentVersionRun_ff52 {
  strings:
    $key_ff52 = { ac 3d [2] 88 33 [2] a3 1f [2] 8d 3d [2] 99 26 [2] 96 3c [2] 88 21 [2] 8a 20 [2] 91 26 [2] 8d 21 [2] 91 0e }

  condition:
    any of them
}