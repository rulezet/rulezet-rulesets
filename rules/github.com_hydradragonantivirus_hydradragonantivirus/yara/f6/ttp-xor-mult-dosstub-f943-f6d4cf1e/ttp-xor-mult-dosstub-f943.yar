rule TTP_XOR_MULT_DOSStub_f943 {
  strings:
    $key_f943 = { ad 2b [2] d9 33 [2] 9e 31 [2] d9 20 [2] 97 2c [2] 9b 26 [2] 8c 2d [2] 97 63 [2] aa }

  condition:
    any of them
}