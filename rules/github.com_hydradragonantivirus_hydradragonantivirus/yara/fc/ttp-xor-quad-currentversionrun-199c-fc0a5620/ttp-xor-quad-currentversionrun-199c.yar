rule TTP_XOR_QUAD_CurrentVersionRun_199c {
  strings:
    $key_199c = { 4a f3 [2] 6e fd [2] 45 d1 [2] 6b f3 [2] 7f e8 [2] 70 f2 [2] 6e ef [2] 6c ee [2] 77 e8 [2] 6b ef [2] 77 c0 }

  condition:
    any of them
}