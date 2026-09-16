rule TTP_XOR_MULT_DOSStub_5fe7 {
  strings:
    $key_5fe7 = { 0b 8f [2] 7f 97 [2] 38 95 [2] 7f 84 [2] 31 88 [2] 3d 82 [2] 2a 89 [2] 31 c7 [2] 0c }

  condition:
    any of them
}