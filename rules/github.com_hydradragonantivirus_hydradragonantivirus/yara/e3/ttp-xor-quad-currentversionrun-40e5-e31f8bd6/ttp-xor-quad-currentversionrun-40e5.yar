rule TTP_XOR_QUAD_CurrentVersionRun_40e5 {
  strings:
    $key_40e5 = { 13 8a [2] 37 84 [2] 1c a8 [2] 32 8a [2] 26 91 [2] 29 8b [2] 37 96 [2] 35 97 [2] 2e 91 [2] 32 96 [2] 2e b9 }

  condition:
    any of them
}