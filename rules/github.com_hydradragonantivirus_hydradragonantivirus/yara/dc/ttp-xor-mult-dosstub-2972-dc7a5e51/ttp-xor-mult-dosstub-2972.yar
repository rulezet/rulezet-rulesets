rule TTP_XOR_MULT_DOSStub_2972 {
  strings:
    $key_2972 = { 7d 1a [2] 09 02 [2] 4e 00 [2] 09 11 [2] 47 1d [2] 4b 17 [2] 5c 1c [2] 47 52 [2] 7a }

  condition:
    any of them
}