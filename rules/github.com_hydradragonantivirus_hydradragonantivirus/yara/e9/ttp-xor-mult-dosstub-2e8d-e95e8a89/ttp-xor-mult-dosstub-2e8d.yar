rule TTP_XOR_MULT_DOSStub_2e8d {
  strings:
    $key_2e8d = { 7a e5 [2] 0e fd [2] 49 ff [2] 0e ee [2] 40 e2 [2] 4c e8 [2] 5b e3 [2] 40 ad [2] 7d }

  condition:
    any of them
}