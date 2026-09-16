rule TTP_XOR_QUAD_CurrentVersionRun_2144 {
  strings:
    $key_2144 = { 72 2b [2] 56 25 [2] 7d 09 [2] 53 2b [2] 47 30 [2] 48 2a [2] 56 37 [2] 54 36 [2] 4f 30 [2] 53 37 [2] 4f 18 }

  condition:
    any of them
}