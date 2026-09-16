rule TTP_XOR_QUAD_CurrentVersionRun_6b68 {
  strings:
    $key_6b68 = { 38 07 [2] 1c 09 [2] 37 25 [2] 19 07 [2] 0d 1c [2] 02 06 [2] 1c 1b [2] 1e 1a [2] 05 1c [2] 19 1b [2] 05 34 }

  condition:
    any of them
}