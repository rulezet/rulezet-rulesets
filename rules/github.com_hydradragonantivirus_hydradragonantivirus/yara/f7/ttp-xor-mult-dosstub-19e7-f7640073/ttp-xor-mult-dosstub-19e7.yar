rule TTP_XOR_MULT_DOSStub_19e7 {
  strings:
    $key_19e7 = { 4d 8f [2] 39 97 [2] 7e 95 [2] 39 84 [2] 77 88 [2] 7b 82 [2] 6c 89 [2] 77 c7 [2] 4a }

  condition:
    any of them
}