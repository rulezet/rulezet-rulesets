rule TTP_XOR_MULT_DOSStub_c48d {
  strings:
    $key_c48d = { 90 e5 [2] e4 fd [2] a3 ff [2] e4 ee [2] aa e2 [2] a6 e8 [2] b1 e3 [2] aa ad [2] 97 }

  condition:
    any of them
}