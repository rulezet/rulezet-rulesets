rule TTP_XOR_MULT_DOSStub_2a67 {
  strings:
    $key_2a67 = { 7e 0f [2] 0a 17 [2] 4d 15 [2] 0a 04 [2] 44 08 [2] 48 02 [2] 5f 09 [2] 44 47 [2] 79 }

  condition:
    any of them
}