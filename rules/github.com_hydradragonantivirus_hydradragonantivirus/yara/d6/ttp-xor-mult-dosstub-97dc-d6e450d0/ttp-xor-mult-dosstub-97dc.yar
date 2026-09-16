rule TTP_XOR_MULT_DOSStub_97dc {
  strings:
    $key_97dc = { c3 b4 [2] b7 ac [2] f0 ae [2] b7 bf [2] f9 b3 [2] f5 b9 [2] e2 b2 [2] f9 fc [2] c4 }

  condition:
    any of them
}