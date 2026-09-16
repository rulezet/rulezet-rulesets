rule TTP_XOR_MULT_DOSStub_5f4c {
  strings:
    $key_5f4c = { 0b 24 [2] 7f 3c [2] 38 3e [2] 7f 2f [2] 31 23 [2] 3d 29 [2] 2a 22 [2] 31 6c [2] 0c }

  condition:
    any of them
}