rule TTP_XOR_MULT_DOSStub_568c {
  strings:
    $key_568c = { 02 e4 [2] 76 fc [2] 31 fe [2] 76 ef [2] 38 e3 [2] 34 e9 [2] 23 e2 [2] 38 ac [2] 05 }

  condition:
    any of them
}