rule TTP_XOR_MULT_DOSStub_2f5f {
  strings:
    $key_2f5f = { 7b 37 [2] 0f 2f [2] 48 2d [2] 0f 3c [2] 41 30 [2] 4d 3a [2] 5a 31 [2] 41 7f [2] 7c }

  condition:
    any of them
}