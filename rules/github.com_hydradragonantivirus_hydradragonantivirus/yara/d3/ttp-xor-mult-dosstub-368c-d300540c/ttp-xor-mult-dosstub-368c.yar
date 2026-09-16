rule TTP_XOR_MULT_DOSStub_368c {
  strings:
    $key_368c = { 62 e4 [2] 16 fc [2] 51 fe [2] 16 ef [2] 58 e3 [2] 54 e9 [2] 43 e2 [2] 58 ac [2] 65 }

  condition:
    any of them
}