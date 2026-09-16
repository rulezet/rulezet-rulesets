rule TTP_XOR_MULT_DOSStub_11d2 {
  strings:
    $key_11d2 = { 45 ba [2] 31 a2 [2] 76 a0 [2] 31 b1 [2] 7f bd [2] 73 b7 [2] 64 bc [2] 7f f2 [2] 42 }

  condition:
    any of them
}