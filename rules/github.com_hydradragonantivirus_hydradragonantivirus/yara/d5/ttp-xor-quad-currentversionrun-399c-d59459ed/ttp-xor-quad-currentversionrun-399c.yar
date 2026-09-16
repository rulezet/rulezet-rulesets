rule TTP_XOR_QUAD_CurrentVersionRun_399c {
  strings:
    $key_399c = { 6a f3 [2] 4e fd [2] 65 d1 [2] 4b f3 [2] 5f e8 [2] 50 f2 [2] 4e ef [2] 4c ee [2] 57 e8 [2] 4b ef [2] 57 c0 }

  condition:
    any of them
}