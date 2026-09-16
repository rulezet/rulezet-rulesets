rule TTP_XOR_MULT_DOSStub_7f6f {
  strings:
    $key_7f6f = { 2b 07 [2] 5f 1f [2] 18 1d [2] 5f 0c [2] 11 00 [2] 1d 0a [2] 0a 01 [2] 11 4f [2] 2c }

  condition:
    any of them
}