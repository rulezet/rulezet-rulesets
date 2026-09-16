rule TTP_XOR_MULT_DOSStub_528c {
  strings:
    $key_528c = { 06 e4 [2] 72 fc [2] 35 fe [2] 72 ef [2] 3c e3 [2] 30 e9 [2] 27 e2 [2] 3c ac [2] 01 }

  condition:
    any of them
}