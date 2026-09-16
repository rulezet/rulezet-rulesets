rule TTP_XOR_MULT_DOSStub_f912 {
  strings:
    $key_f912 = { ad 7a [2] d9 62 [2] 9e 60 [2] d9 71 [2] 97 7d [2] 9b 77 [2] 8c 7c [2] 97 32 [2] aa }

  condition:
    any of them
}