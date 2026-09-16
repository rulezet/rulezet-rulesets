rule TTP_XOR_MULT_DOSStub_6f04 {
  strings:
    $key_6f04 = { 3b 6c [2] 4f 74 [2] 08 76 [2] 4f 67 [2] 01 6b [2] 0d 61 [2] 1a 6a [2] 01 24 [2] 3c }

  condition:
    any of them
}