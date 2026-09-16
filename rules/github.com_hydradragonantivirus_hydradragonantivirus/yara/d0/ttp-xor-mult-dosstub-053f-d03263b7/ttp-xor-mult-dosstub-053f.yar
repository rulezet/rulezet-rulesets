rule TTP_XOR_MULT_DOSStub_053f {
  strings:
    $key_053f = { 51 57 [2] 25 4f [2] 62 4d [2] 25 5c [2] 6b 50 [2] 67 5a [2] 70 51 [2] 6b 1f [2] 56 }

  condition:
    any of them
}