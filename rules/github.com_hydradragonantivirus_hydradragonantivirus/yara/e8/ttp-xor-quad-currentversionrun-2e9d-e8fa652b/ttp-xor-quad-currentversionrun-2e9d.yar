rule TTP_XOR_QUAD_CurrentVersionRun_2e9d {
  strings:
    $key_2e9d = { 7d f2 [2] 59 fc [2] 72 d0 [2] 5c f2 [2] 48 e9 [2] 47 f3 [2] 59 ee [2] 5b ef [2] 40 e9 [2] 5c ee [2] 40 c1 }

  condition:
    any of them
}