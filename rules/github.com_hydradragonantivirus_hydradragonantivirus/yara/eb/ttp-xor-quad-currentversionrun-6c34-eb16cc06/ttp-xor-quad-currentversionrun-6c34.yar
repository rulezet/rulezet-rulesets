rule TTP_XOR_QUAD_CurrentVersionRun_6c34 {
  strings:
    $key_6c34 = { 3f 5b [2] 1b 55 [2] 30 79 [2] 1e 5b [2] 0a 40 [2] 05 5a [2] 1b 47 [2] 19 46 [2] 02 40 [2] 1e 47 [2] 02 68 }

  condition:
    any of them
}