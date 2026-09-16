rule TTP_XOR_QUAD_CurrentVersionRun_799c {
  strings:
    $key_799c = { 2a f3 [2] 0e fd [2] 25 d1 [2] 0b f3 [2] 1f e8 [2] 10 f2 [2] 0e ef [2] 0c ee [2] 17 e8 [2] 0b ef [2] 17 c0 }

  condition:
    any of them
}