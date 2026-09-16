rule TTP_XOR_QUAD_CurrentVersionRun_6c39 {
  strings:
    $key_6c39 = { 3f 56 [2] 1b 58 [2] 30 74 [2] 1e 56 [2] 0a 4d [2] 05 57 [2] 1b 4a [2] 19 4b [2] 02 4d [2] 1e 4a [2] 02 65 }

  condition:
    any of them
}