rule TTP_XOR_MULT_DOSStub_f933 {
  strings:
    $key_f933 = { ad 5b [2] d9 43 [2] 9e 41 [2] d9 50 [2] 97 5c [2] 9b 56 [2] 8c 5d [2] 97 13 [2] aa }

  condition:
    any of them
}