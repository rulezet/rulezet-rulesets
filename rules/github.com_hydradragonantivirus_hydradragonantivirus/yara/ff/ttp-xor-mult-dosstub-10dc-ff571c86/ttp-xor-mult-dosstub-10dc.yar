rule TTP_XOR_MULT_DOSStub_10dc {
  strings:
    $key_10dc = { 44 b4 [2] 30 ac [2] 77 ae [2] 30 bf [2] 7e b3 [2] 72 b9 [2] 65 b2 [2] 7e fc [2] 43 }

  condition:
    any of them
}