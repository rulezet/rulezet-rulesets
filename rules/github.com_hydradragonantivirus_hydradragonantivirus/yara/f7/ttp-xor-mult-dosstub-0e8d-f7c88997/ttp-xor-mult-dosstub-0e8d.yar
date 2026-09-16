rule TTP_XOR_MULT_DOSStub_0e8d {
  strings:
    $key_0e8d = { 5a e5 [2] 2e fd [2] 69 ff [2] 2e ee [2] 60 e2 [2] 6c e8 [2] 7b e3 [2] 60 ad [2] 5d }

  condition:
    any of them
}