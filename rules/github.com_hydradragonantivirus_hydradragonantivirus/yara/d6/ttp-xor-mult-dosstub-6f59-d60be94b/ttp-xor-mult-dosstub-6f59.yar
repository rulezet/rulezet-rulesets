rule TTP_XOR_MULT_DOSStub_6f59 {
  strings:
    $key_6f59 = { 3b 31 [2] 4f 29 [2] 08 2b [2] 4f 3a [2] 01 36 [2] 0d 3c [2] 1a 37 [2] 01 79 [2] 3c }

  condition:
    any of them
}