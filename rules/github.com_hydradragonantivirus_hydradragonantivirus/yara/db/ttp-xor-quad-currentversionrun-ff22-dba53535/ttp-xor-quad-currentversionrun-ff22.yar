rule TTP_XOR_QUAD_CurrentVersionRun_ff22 {
  strings:
    $key_ff22 = { ac 4d [2] 88 43 [2] a3 6f [2] 8d 4d [2] 99 56 [2] 96 4c [2] 88 51 [2] 8a 50 [2] 91 56 [2] 8d 51 [2] 91 7e }

  condition:
    any of them
}