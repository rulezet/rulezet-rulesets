rule TTP_XOR_QUAD_CurrentVersionRun_099c {
  strings:
    $key_099c = { 5a f3 [2] 7e fd [2] 55 d1 [2] 7b f3 [2] 6f e8 [2] 60 f2 [2] 7e ef [2] 7c ee [2] 67 e8 [2] 7b ef [2] 67 c0 }

  condition:
    any of them
}