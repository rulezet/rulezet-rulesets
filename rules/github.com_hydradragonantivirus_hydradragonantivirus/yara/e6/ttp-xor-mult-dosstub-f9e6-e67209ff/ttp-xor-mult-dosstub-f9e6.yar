rule TTP_XOR_MULT_DOSStub_f9e6 {
  strings:
    $key_f9e6 = { ad 8e [2] d9 96 [2] 9e 94 [2] d9 85 [2] 97 89 [2] 9b 83 [2] 8c 88 [2] 97 c6 [2] aa }

  condition:
    any of them
}