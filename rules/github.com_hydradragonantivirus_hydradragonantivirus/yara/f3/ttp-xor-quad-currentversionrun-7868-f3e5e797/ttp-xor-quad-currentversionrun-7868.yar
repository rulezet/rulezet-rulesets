rule TTP_XOR_QUAD_CurrentVersionRun_7868 {
  strings:
    $key_7868 = { 2b 07 [2] 0f 09 [2] 24 25 [2] 0a 07 [2] 1e 1c [2] 11 06 [2] 0f 1b [2] 0d 1a [2] 16 1c [2] 0a 1b [2] 16 34 }

  condition:
    any of them
}