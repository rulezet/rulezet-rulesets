rule TTP_XOR_MULT_DOSStub_6fe3 {
  strings:
    $key_6fe3 = { 3b 8b [2] 4f 93 [2] 08 91 [2] 4f 80 [2] 01 8c [2] 0d 86 [2] 1a 8d [2] 01 c3 [2] 3c }

  condition:
    any of them
}