rule TTP_XOR_MULT_DOSStub_f963 {
  strings:
    $key_f963 = { ad 0b [2] d9 13 [2] 9e 11 [2] d9 00 [2] 97 0c [2] 9b 06 [2] 8c 0d [2] 97 43 [2] aa }

  condition:
    any of them
}