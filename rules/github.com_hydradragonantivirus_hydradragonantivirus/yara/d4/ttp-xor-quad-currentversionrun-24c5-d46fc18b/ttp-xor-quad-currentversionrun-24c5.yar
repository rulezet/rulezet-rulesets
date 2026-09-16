rule TTP_XOR_QUAD_CurrentVersionRun_24c5 {
  strings:
    $key_24c5 = { 77 aa [2] 53 a4 [2] 78 88 [2] 56 aa [2] 42 b1 [2] 4d ab [2] 53 b6 [2] 51 b7 [2] 4a b1 [2] 56 b6 [2] 4a 99 }

  condition:
    any of them
}