rule TTP_XOR_MULT_DOSStub_6fe5 {
  strings:
    $key_6fe5 = { 3b 8d [2] 4f 95 [2] 08 97 [2] 4f 86 [2] 01 8a [2] 0d 80 [2] 1a 8b [2] 01 c5 [2] 3c }

  condition:
    any of them
}