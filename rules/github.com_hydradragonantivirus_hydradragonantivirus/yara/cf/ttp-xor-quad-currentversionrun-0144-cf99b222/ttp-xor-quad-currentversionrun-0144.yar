rule TTP_XOR_QUAD_CurrentVersionRun_0144 {
  strings:
    $key_0144 = { 52 2b [2] 76 25 [2] 5d 09 [2] 73 2b [2] 67 30 [2] 68 2a [2] 76 37 [2] 74 36 [2] 6f 30 [2] 73 37 [2] 6f 18 }

  condition:
    any of them
}