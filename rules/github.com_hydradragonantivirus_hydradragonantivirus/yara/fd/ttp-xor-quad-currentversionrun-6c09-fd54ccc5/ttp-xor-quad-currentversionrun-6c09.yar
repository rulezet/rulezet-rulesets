rule TTP_XOR_QUAD_CurrentVersionRun_6c09 {
  strings:
    $key_6c09 = { 3f 66 [2] 1b 68 [2] 30 44 [2] 1e 66 [2] 0a 7d [2] 05 67 [2] 1b 7a [2] 19 7b [2] 02 7d [2] 1e 7a [2] 02 55 }

  condition:
    any of them
}