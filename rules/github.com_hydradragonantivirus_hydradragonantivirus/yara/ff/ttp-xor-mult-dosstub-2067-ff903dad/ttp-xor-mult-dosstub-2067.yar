rule TTP_XOR_MULT_DOSStub_2067 {
  strings:
    $key_2067 = { 74 0f [2] 00 17 [2] 47 15 [2] 00 04 [2] 4e 08 [2] 42 02 [2] 55 09 [2] 4e 47 [2] 73 }

  condition:
    any of them
}