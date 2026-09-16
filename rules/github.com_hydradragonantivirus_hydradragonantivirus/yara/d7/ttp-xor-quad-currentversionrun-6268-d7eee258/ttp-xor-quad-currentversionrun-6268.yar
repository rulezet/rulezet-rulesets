rule TTP_XOR_QUAD_CurrentVersionRun_6268 {
  strings:
    $key_6268 = { 31 07 [2] 15 09 [2] 3e 25 [2] 10 07 [2] 04 1c [2] 0b 06 [2] 15 1b [2] 17 1a [2] 0c 1c [2] 10 1b [2] 0c 34 }

  condition:
    any of them
}