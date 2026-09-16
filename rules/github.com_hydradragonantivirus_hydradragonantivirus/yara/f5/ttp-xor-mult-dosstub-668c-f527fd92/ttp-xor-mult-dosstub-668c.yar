rule TTP_XOR_MULT_DOSStub_668c {
  strings:
    $key_668c = { 32 e4 [2] 46 fc [2] 01 fe [2] 46 ef [2] 08 e3 [2] 04 e9 [2] 13 e2 [2] 08 ac [2] 35 }

  condition:
    any of them
}