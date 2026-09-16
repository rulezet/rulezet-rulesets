rule TTP_XOR_QUAD_CurrentVersionRun_0529 {
  strings:
    $key_0529 = { 56 46 [2] 72 48 [2] 59 64 [2] 77 46 [2] 63 5d [2] 6c 47 [2] 72 5a [2] 70 5b [2] 6b 5d [2] 77 5a [2] 6b 75 }

  condition:
    any of them
}