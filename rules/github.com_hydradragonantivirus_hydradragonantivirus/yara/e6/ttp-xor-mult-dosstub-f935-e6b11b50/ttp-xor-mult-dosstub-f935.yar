rule TTP_XOR_MULT_DOSStub_f935 {
  strings:
    $key_f935 = { ad 5d [2] d9 45 [2] 9e 47 [2] d9 56 [2] 97 5a [2] 9b 50 [2] 8c 5b [2] 97 15 [2] aa }

  condition:
    any of them
}