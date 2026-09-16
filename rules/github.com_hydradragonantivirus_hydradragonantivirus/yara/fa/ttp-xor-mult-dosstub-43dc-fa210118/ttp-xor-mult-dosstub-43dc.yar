rule TTP_XOR_MULT_DOSStub_43dc {
  strings:
    $key_43dc = { 17 b4 [2] 63 ac [2] 24 ae [2] 63 bf [2] 2d b3 [2] 21 b9 [2] 36 b2 [2] 2d fc [2] 10 }

  condition:
    any of them
}