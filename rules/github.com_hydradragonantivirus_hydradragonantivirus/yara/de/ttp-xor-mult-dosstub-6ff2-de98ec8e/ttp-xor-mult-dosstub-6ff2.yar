rule TTP_XOR_MULT_DOSStub_6ff2 {
  strings:
    $key_6ff2 = { 3b 9a [2] 4f 82 [2] 08 80 [2] 4f 91 [2] 01 9d [2] 0d 97 [2] 1a 9c [2] 01 d2 [2] 3c }

  condition:
    any of them
}