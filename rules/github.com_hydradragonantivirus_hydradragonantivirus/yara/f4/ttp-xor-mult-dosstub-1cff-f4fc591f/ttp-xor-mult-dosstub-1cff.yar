rule TTP_XOR_MULT_DOSStub_1cff {
  strings:
    $key_1cff = { 48 97 [2] 3c 8f [2] 7b 8d [2] 3c 9c [2] 72 90 [2] 7e 9a [2] 69 91 [2] 72 df [2] 4f }

  condition:
    any of them
}