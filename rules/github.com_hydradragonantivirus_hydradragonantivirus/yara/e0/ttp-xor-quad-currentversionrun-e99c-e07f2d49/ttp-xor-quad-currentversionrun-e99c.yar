rule TTP_XOR_QUAD_CurrentVersionRun_e99c {
  strings:
    $key_e99c = { ba f3 [2] 9e fd [2] b5 d1 [2] 9b f3 [2] 8f e8 [2] 80 f2 [2] 9e ef [2] 9c ee [2] 87 e8 [2] 9b ef [2] 87 c0 }

  condition:
    any of them
}