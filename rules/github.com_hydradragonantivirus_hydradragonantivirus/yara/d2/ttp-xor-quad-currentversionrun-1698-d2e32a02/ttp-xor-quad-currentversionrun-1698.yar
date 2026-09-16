rule TTP_XOR_QUAD_CurrentVersionRun_1698 {
  strings:
    $key_1698 = { 45 f7 [2] 61 f9 [2] 4a d5 [2] 64 f7 [2] 70 ec [2] 7f f6 [2] 61 eb [2] 63 ea [2] 78 ec [2] 64 eb [2] 78 c4 }

  condition:
    any of them
}