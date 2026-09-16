rule TTP_XOR_MULT_DOSStub_f911 {
  strings:
    $key_f911 = { ad 79 [2] d9 61 [2] 9e 63 [2] d9 72 [2] 97 7e [2] 9b 74 [2] 8c 7f [2] 97 31 [2] aa }

  condition:
    any of them
}