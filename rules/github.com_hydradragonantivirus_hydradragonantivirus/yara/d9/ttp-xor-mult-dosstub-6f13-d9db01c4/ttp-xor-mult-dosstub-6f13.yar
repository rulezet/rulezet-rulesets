rule TTP_XOR_MULT_DOSStub_6f13 {
  strings:
    $key_6f13 = { 3b 7b [2] 4f 63 [2] 08 61 [2] 4f 70 [2] 01 7c [2] 0d 76 [2] 1a 7d [2] 01 33 [2] 3c }

  condition:
    any of them
}