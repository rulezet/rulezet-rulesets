rule TTP_XOR_MULT_DOSStub_f967 {
  strings:
    $key_f967 = { ad 0f [2] d9 17 [2] 9e 15 [2] d9 04 [2] 97 08 [2] 9b 02 [2] 8c 09 [2] 97 47 [2] aa }

  condition:
    any of them
}