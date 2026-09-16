rule TTP_XOR_MULT_DOSStub_25dc {
  strings:
    $key_25dc = { 71 b4 [2] 05 ac [2] 42 ae [2] 05 bf [2] 4b b3 [2] 47 b9 [2] 50 b2 [2] 4b fc [2] 76 }

  condition:
    any of them
}