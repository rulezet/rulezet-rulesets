rule TTP_XOR_MULT_DOSStub_4f6f {
  strings:
    $key_4f6f = { 1b 07 [2] 6f 1f [2] 28 1d [2] 6f 0c [2] 21 00 [2] 2d 0a [2] 3a 01 [2] 21 4f [2] 1c }

  condition:
    any of them
}