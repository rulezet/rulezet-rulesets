rule TTP_XOR_MULT_DOSStub_6f25 {
  strings:
    $key_6f25 = { 3b 4d [2] 4f 55 [2] 08 57 [2] 4f 46 [2] 01 4a [2] 0d 40 [2] 1a 4b [2] 01 05 [2] 3c }

  condition:
    any of them
}