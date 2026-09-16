rule TTP_XOR_MULT_DOSStub_f55f {
  strings:
    $key_f55f = { a1 37 [2] d5 2f [2] 92 2d [2] d5 3c [2] 9b 30 [2] 97 3a [2] 80 31 [2] 9b 7f [2] a6 }

  condition:
    any of them
}