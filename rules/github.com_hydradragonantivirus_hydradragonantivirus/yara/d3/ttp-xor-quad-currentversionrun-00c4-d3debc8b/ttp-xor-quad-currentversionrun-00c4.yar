rule TTP_XOR_QUAD_CurrentVersionRun_00c4 {
  strings:
    $key_00c4 = { 53 ab [2] 77 a5 [2] 5c 89 [2] 72 ab [2] 66 b0 [2] 69 aa [2] 77 b7 [2] 75 b6 [2] 6e b0 [2] 72 b7 [2] 6e 98 }

  condition:
    any of them
}