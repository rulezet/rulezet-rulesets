rule TTP_XOR_MULT_DOSStub_92dc {
  strings:
    $key_92dc = { c6 b4 [2] b2 ac [2] f5 ae [2] b2 bf [2] fc b3 [2] f0 b9 [2] e7 b2 [2] fc fc [2] c1 }

  condition:
    any of them
}