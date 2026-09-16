rule TTP_XOR_MULT_DOSStub_61dc {
  strings:
    $key_61dc = { 35 b4 [2] 41 ac [2] 06 ae [2] 41 bf [2] 0f b3 [2] 03 b9 [2] 14 b2 [2] 0f fc [2] 32 }

  condition:
    any of them
}