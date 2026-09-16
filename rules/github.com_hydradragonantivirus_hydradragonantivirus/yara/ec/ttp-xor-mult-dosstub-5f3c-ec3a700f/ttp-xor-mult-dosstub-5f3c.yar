rule TTP_XOR_MULT_DOSStub_5f3c {
  strings:
    $key_5f3c = { 0b 54 [2] 7f 4c [2] 38 4e [2] 7f 5f [2] 31 53 [2] 3d 59 [2] 2a 52 [2] 31 1c [2] 0c }

  condition:
    any of them
}