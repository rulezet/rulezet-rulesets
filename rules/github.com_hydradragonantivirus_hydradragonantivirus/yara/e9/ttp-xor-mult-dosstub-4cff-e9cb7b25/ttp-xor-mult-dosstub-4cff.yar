rule TTP_XOR_MULT_DOSStub_4cff {
  strings:
    $key_4cff = { 18 97 [2] 6c 8f [2] 2b 8d [2] 6c 9c [2] 22 90 [2] 2e 9a [2] 39 91 [2] 22 df [2] 1f }

  condition:
    any of them
}