rule TTP_XOR_MULT_DOSStub_f954 {
  strings:
    $key_f954 = { ad 3c [2] d9 24 [2] 9e 26 [2] d9 37 [2] 97 3b [2] 9b 31 [2] 8c 3a [2] 97 74 [2] aa }

  condition:
    any of them
}