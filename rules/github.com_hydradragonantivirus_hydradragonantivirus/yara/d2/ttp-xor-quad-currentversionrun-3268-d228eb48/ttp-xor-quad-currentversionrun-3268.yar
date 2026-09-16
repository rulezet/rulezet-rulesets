rule TTP_XOR_QUAD_CurrentVersionRun_3268 {
  strings:
    $key_3268 = { 61 07 [2] 45 09 [2] 6e 25 [2] 40 07 [2] 54 1c [2] 5b 06 [2] 45 1b [2] 47 1a [2] 5c 1c [2] 40 1b [2] 5c 34 }

  condition:
    any of them
}