rule TTP_XOR_MULT_DOSStub_f971 {
  strings:
    $key_f971 = { ad 19 [2] d9 01 [2] 9e 03 [2] d9 12 [2] 97 1e [2] 9b 14 [2] 8c 1f [2] 97 51 [2] aa }

  condition:
    any of them
}