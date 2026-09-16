rule TTP_XOR_MULT_DOSStub_f913 {
  strings:
    $key_f913 = { ad 7b [2] d9 63 [2] 9e 61 [2] d9 70 [2] 97 7c [2] 9b 76 [2] 8c 7d [2] 97 33 [2] aa }

  condition:
    any of them
}