rule TTP_XOR_MULT_DOSStub_6f38 {
  strings:
    $key_6f38 = { 3b 50 [2] 4f 48 [2] 08 4a [2] 4f 5b [2] 01 57 [2] 0d 5d [2] 1a 56 [2] 01 18 [2] 3c }

  condition:
    any of them
}