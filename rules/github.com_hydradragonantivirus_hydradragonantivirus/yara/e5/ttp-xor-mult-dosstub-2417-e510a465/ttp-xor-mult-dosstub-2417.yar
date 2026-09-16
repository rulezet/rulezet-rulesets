rule TTP_XOR_MULT_DOSStub_2417 {
  strings:
    $key_2417 = { 70 7f [2] 04 67 [2] 43 65 [2] 04 74 [2] 4a 78 [2] 46 72 [2] 51 79 [2] 4a 37 [2] 77 }

  condition:
    any of them
}