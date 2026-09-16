rule TTP_XOR_MULT_DOSStub_f94e {
  strings:
    $key_f94e = { ad 26 [2] d9 3e [2] 9e 3c [2] d9 2d [2] 97 21 [2] 9b 2b [2] 8c 20 [2] 97 6e [2] aa }

  condition:
    any of them
}