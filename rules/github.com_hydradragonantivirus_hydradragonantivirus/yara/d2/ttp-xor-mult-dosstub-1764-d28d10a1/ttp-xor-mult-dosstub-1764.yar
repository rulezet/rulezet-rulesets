rule TTP_XOR_MULT_DOSStub_1764 {
  strings:
    $key_1764 = { 43 0c [2] 37 14 [2] 70 16 [2] 37 07 [2] 79 0b [2] 75 01 [2] 62 0a [2] 79 44 [2] 44 }

  condition:
    any of them
}