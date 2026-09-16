rule TTP_XOR_MULT_DOSStub_93dc {
  strings:
    $key_93dc = { c7 b4 [2] b3 ac [2] f4 ae [2] b3 bf [2] fd b3 [2] f1 b9 [2] e6 b2 [2] fd fc [2] c0 }

  condition:
    any of them
}