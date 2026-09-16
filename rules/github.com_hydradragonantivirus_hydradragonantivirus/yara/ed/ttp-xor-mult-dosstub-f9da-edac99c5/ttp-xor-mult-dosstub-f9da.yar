rule TTP_XOR_MULT_DOSStub_f9da {
  strings:
    $key_f9da = { ad b2 [2] d9 aa [2] 9e a8 [2] d9 b9 [2] 97 b5 [2] 9b bf [2] 8c b4 [2] 97 fa [2] aa }

  condition:
    any of them
}