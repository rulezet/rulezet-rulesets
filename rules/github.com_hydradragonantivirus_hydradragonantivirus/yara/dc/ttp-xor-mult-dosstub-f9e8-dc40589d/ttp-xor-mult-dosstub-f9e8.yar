rule TTP_XOR_MULT_DOSStub_f9e8 {
  strings:
    $key_f9e8 = { ad 80 [2] d9 98 [2] 9e 9a [2] d9 8b [2] 97 87 [2] 9b 8d [2] 8c 86 [2] 97 c8 [2] aa }

  condition:
    any of them
}