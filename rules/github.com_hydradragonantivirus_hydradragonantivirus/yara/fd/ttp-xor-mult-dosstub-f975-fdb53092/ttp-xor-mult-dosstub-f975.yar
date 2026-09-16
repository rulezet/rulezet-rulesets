rule TTP_XOR_MULT_DOSStub_f975 {
  strings:
    $key_f975 = { ad 1d [2] d9 05 [2] 9e 07 [2] d9 16 [2] 97 1a [2] 9b 10 [2] 8c 1b [2] 97 55 [2] aa }

  condition:
    any of them
}