rule TTP_XOR_MULT_DOSStub_3f04 {
  strings:
    $key_3f04 = { 6b 6c [2] 1f 74 [2] 58 76 [2] 1f 67 [2] 51 6b [2] 5d 61 [2] 4a 6a [2] 51 24 [2] 6c }

  condition:
    any of them
}