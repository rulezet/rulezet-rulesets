rule TTP_XOR_MULT_DOSStub_da8d {
  strings:
    $key_da8d = { 8e e5 [2] fa fd [2] bd ff [2] fa ee [2] b4 e2 [2] b8 e8 [2] af e3 [2] b4 ad [2] 89 }

  condition:
    any of them
}