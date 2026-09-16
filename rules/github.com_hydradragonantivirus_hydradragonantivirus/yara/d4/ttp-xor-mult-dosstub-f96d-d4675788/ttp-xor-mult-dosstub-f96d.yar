rule TTP_XOR_MULT_DOSStub_f96d {
  strings:
    $key_f96d = { ad 05 [2] d9 1d [2] 9e 1f [2] d9 0e [2] 97 02 [2] 9b 08 [2] 8c 03 [2] 97 4d [2] aa }

  condition:
    any of them
}