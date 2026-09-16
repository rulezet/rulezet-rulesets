rule TTP_XOR_QUAD_CurrentVersionRun_2498 {
  strings:
    $key_2498 = { 77 f7 [2] 53 f9 [2] 78 d5 [2] 56 f7 [2] 42 ec [2] 4d f6 [2] 53 eb [2] 51 ea [2] 4a ec [2] 56 eb [2] 4a c4 }

  condition:
    any of them
}