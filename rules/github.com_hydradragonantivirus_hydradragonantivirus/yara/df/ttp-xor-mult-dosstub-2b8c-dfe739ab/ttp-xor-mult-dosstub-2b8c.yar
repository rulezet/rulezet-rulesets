rule TTP_XOR_MULT_DOSStub_2b8c {
  strings:
    $key_2b8c = { 7f e4 [2] 0b fc [2] 4c fe [2] 0b ef [2] 45 e3 [2] 49 e9 [2] 5e e2 [2] 45 ac [2] 78 }

  condition:
    any of them
}