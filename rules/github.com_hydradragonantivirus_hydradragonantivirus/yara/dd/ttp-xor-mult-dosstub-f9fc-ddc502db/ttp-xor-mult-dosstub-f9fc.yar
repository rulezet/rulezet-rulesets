rule TTP_XOR_MULT_DOSStub_f9fc {
  strings:
    $key_f9fc = { ad 94 [2] d9 8c [2] 9e 8e [2] d9 9f [2] 97 93 [2] 9b 99 [2] 8c 92 [2] 97 dc [2] aa }

  condition:
    any of them
}