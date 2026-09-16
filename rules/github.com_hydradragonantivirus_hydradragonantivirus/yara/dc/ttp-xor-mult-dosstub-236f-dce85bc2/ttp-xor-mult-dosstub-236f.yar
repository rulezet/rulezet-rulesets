rule TTP_XOR_MULT_DOSStub_236f {
  strings:
    $key_236f = { 77 07 [2] 03 1f [2] 44 1d [2] 03 0c [2] 4d 00 [2] 41 0a [2] 56 01 [2] 4d 4f [2] 70 }

  condition:
    any of them
}