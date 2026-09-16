rule TTP_XOR_MULT_DOSStub_ff92 {
  strings:
    $key_ff92 = { ab fa [2] df e2 [2] 98 e0 [2] df f1 [2] 91 fd [2] 9d f7 [2] 8a fc [2] 91 b2 [2] ac }

  condition:
    any of them
}