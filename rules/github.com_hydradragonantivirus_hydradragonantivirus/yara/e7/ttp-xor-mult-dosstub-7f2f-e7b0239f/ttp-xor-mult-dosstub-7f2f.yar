rule TTP_XOR_MULT_DOSStub_7f2f {
  strings:
    $key_7f2f = { 2b 47 [2] 5f 5f [2] 18 5d [2] 5f 4c [2] 11 40 [2] 1d 4a [2] 0a 41 [2] 11 0f [2] 2c }

  condition:
    any of them
}