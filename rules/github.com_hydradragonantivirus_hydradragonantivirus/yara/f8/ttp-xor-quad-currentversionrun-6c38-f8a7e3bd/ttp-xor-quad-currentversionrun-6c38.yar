rule TTP_XOR_QUAD_CurrentVersionRun_6c38 {
  strings:
    $key_6c38 = { 3f 57 [2] 1b 59 [2] 30 75 [2] 1e 57 [2] 0a 4c [2] 05 56 [2] 1b 4b [2] 19 4a [2] 02 4c [2] 1e 4b [2] 02 64 }

  condition:
    any of them
}