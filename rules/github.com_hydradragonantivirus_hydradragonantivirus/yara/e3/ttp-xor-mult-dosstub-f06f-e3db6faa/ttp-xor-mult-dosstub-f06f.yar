rule TTP_XOR_MULT_DOSStub_f06f {
  strings:
    $key_f06f = { a4 07 [2] d0 1f [2] 97 1d [2] d0 0c [2] 9e 00 [2] 92 0a [2] 85 01 [2] 9e 4f [2] a3 }

  condition:
    any of them
}