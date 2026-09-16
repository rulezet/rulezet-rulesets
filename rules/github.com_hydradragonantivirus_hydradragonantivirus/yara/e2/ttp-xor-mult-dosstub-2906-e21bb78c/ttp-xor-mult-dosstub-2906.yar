rule TTP_XOR_MULT_DOSStub_2906 {
  strings:
    $key_2906 = { 7d 6e [2] 09 76 [2] 4e 74 [2] 09 65 [2] 47 69 [2] 4b 63 [2] 5c 68 [2] 47 26 [2] 7a }

  condition:
    any of them
}