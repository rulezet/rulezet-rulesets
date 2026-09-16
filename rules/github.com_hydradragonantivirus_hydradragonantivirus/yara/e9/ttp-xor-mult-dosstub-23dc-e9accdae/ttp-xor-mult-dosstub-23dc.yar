rule TTP_XOR_MULT_DOSStub_23dc {
  strings:
    $key_23dc = { 77 b4 [2] 03 ac [2] 44 ae [2] 03 bf [2] 4d b3 [2] 41 b9 [2] 56 b2 [2] 4d fc [2] 70 }

  condition:
    any of them
}