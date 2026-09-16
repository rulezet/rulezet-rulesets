rule TTP_XOR_QUAD_CurrentVersionRun_3c68 {
  strings:
    $key_3c68 = { 6f 07 [2] 4b 09 [2] 60 25 [2] 4e 07 [2] 5a 1c [2] 55 06 [2] 4b 1b [2] 49 1a [2] 52 1c [2] 4e 1b [2] 52 34 }

  condition:
    any of them
}