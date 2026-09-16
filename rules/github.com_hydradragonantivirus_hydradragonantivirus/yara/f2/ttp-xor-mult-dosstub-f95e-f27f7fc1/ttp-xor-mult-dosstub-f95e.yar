rule TTP_XOR_MULT_DOSStub_f95e {
  strings:
    $key_f95e = { ad 36 [2] d9 2e [2] 9e 2c [2] d9 3d [2] 97 31 [2] 9b 3b [2] 8c 30 [2] 97 7e [2] aa }

  condition:
    any of them
}