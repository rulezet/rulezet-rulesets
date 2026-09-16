rule TTP_XOR_QUAD_CurrentVersionRun_7698 {
  strings:
    $key_7698 = { 25 f7 [2] 01 f9 [2] 2a d5 [2] 04 f7 [2] 10 ec [2] 1f f6 [2] 01 eb [2] 03 ea [2] 18 ec [2] 04 eb [2] 18 c4 }

  condition:
    any of them
}