rule TTP_XOR_MULT_DOSStub_f94c {
  strings:
    $key_f94c = { ad 24 [2] d9 3c [2] 9e 3e [2] d9 2f [2] 97 23 [2] 9b 29 [2] 8c 22 [2] 97 6c [2] aa }

  condition:
    any of them
}