rule TTP_XOR_MULT_DOSStub_cedf {
  strings:
    $key_cedf = { 9a b7 [2] ee af [2] a9 ad [2] ee bc [2] a0 b0 [2] ac ba [2] bb b1 [2] a0 ff [2] 9d }

  condition:
    any of them
}