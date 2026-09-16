rule TTP_XOR_MULT_DOSStub_f948 {
  strings:
    $key_f948 = { ad 20 [2] d9 38 [2] 9e 3a [2] d9 2b [2] 97 27 [2] 9b 2d [2] 8c 26 [2] 97 68 [2] aa }

  condition:
    any of them
}