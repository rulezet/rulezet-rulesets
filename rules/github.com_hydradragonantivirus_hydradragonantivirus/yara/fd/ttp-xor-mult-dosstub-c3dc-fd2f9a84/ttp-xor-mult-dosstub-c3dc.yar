rule TTP_XOR_MULT_DOSStub_c3dc {
  strings:
    $key_c3dc = { 97 b4 [2] e3 ac [2] a4 ae [2] e3 bf [2] ad b3 [2] a1 b9 [2] b6 b2 [2] ad fc [2] 90 }

  condition:
    any of them
}