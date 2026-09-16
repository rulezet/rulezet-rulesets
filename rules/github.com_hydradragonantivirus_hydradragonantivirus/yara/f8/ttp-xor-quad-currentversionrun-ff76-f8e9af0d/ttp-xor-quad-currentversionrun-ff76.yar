rule TTP_XOR_QUAD_CurrentVersionRun_ff76 {
  strings:
    $key_ff76 = { ac 19 [2] 88 17 [2] a3 3b [2] 8d 19 [2] 99 02 [2] 96 18 [2] 88 05 [2] 8a 04 [2] 91 02 [2] 8d 05 [2] 91 2a }

  condition:
    any of them
}