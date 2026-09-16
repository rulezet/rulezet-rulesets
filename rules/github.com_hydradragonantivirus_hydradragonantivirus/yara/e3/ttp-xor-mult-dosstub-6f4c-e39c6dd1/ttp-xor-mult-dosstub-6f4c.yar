rule TTP_XOR_MULT_DOSStub_6f4c {
  strings:
    $key_6f4c = { 3b 24 [2] 4f 3c [2] 08 3e [2] 4f 2f [2] 01 23 [2] 0d 29 [2] 1a 22 [2] 01 6c [2] 3c }

  condition:
    any of them
}