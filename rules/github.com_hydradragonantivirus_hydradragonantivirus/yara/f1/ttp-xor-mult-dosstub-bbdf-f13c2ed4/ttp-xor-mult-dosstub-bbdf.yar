rule TTP_XOR_MULT_DOSStub_bbdf {
  strings:
    $key_bbdf = { ef b7 [2] 9b af [2] dc ad [2] 9b bc [2] d5 b0 [2] d9 ba [2] ce b1 [2] d5 ff [2] e8 }

  condition:
    any of them
}