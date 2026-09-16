rule TTP_XOR_MULT_DOSStub_7bff {
  strings:
    $key_7bff = { 2f 97 [2] 5b 8f [2] 1c 8d [2] 5b 9c [2] 15 90 [2] 19 9a [2] 0e 91 [2] 15 df [2] 28 }

  condition:
    any of them
}