rule TTP_XOR_MULT_DOSStub_2940 {
  strings:
    $key_2940 = { 7d 28 [2] 09 30 [2] 4e 32 [2] 09 23 [2] 47 2f [2] 4b 25 [2] 5c 2e [2] 47 60 [2] 7a }

  condition:
    any of them
}