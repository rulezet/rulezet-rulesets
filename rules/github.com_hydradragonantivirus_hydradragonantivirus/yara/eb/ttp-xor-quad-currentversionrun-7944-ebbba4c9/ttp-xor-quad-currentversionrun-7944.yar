rule TTP_XOR_QUAD_CurrentVersionRun_7944 {
  strings:
    $key_7944 = { 2a 2b [2] 0e 25 [2] 25 09 [2] 0b 2b [2] 1f 30 [2] 10 2a [2] 0e 37 [2] 0c 36 [2] 17 30 [2] 0b 37 [2] 17 18 }

  condition:
    any of them
}