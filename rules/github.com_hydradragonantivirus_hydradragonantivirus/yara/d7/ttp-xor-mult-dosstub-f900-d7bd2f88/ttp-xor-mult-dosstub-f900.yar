rule TTP_XOR_MULT_DOSStub_f900 {
  strings:
    $key_f900 = { ad 68 [2] d9 70 [2] 9e 72 [2] d9 63 [2] 97 6f [2] 9b 65 [2] 8c 6e [2] 97 20 [2] aa }

  condition:
    any of them
}