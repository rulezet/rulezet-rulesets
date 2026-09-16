rule TTP_XOR_MULT_DOSStub_2917 {
  strings:
    $key_2917 = { 7d 7f [2] 09 67 [2] 4e 65 [2] 09 74 [2] 47 78 [2] 4b 72 [2] 5c 79 [2] 47 37 [2] 7a }

  condition:
    any of them
}