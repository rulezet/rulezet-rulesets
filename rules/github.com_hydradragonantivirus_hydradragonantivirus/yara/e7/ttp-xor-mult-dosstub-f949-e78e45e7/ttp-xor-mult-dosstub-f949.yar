rule TTP_XOR_MULT_DOSStub_f949 {
  strings:
    $key_f949 = { ad 21 [2] d9 39 [2] 9e 3b [2] d9 2a [2] 97 26 [2] 9b 2c [2] 8c 27 [2] 97 69 [2] aa }

  condition:
    any of them
}