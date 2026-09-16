rule TTP_XOR_MULT_DOSStub_f9ed {
  strings:
    $key_f9ed = { ad 85 [2] d9 9d [2] 9e 9f [2] d9 8e [2] 97 82 [2] 9b 88 [2] 8c 83 [2] 97 cd [2] aa }

  condition:
    any of them
}