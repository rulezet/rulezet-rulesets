rule TTP_XOR_QUAD_CurrentVersionRun_5769 {
  strings:
    $key_5769 = { 04 06 [2] 20 08 [2] 0b 24 [2] 25 06 [2] 31 1d [2] 3e 07 [2] 20 1a [2] 22 1b [2] 39 1d [2] 25 1a [2] 39 35 }

  condition:
    any of them
}