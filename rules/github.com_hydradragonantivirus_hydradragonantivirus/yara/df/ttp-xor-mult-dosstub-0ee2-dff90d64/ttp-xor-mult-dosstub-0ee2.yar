rule TTP_XOR_MULT_DOSStub_0ee2 {
  strings:
    $key_0ee2 = { 5a 8a [2] 2e 92 [2] 69 90 [2] 2e 81 [2] 60 8d [2] 6c 87 [2] 7b 8c [2] 60 c2 [2] 5d }

  condition:
    any of them
}