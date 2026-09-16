rule TTP_XOR_MULT_DOSStub_16dc {
  strings:
    $key_16dc = { 42 b4 [2] 36 ac [2] 71 ae [2] 36 bf [2] 78 b3 [2] 74 b9 [2] 63 b2 [2] 78 fc [2] 45 }

  condition:
    any of them
}