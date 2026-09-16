rule TTP_XOR_MULT_DOSStub_f928 {
  strings:
    $key_f928 = { ad 40 [2] d9 58 [2] 9e 5a [2] d9 4b [2] 97 47 [2] 9b 4d [2] 8c 46 [2] 97 08 [2] aa }

  condition:
    any of them
}