rule TTP_XOR_QUAD_CurrentVersionRun_4939 {
  strings:
    $key_4939 = { 1a 56 [2] 3e 58 [2] 15 74 [2] 3b 56 [2] 2f 4d [2] 20 57 [2] 3e 4a [2] 3c 4b [2] 27 4d [2] 3b 4a [2] 27 65 }

  condition:
    any of them
}