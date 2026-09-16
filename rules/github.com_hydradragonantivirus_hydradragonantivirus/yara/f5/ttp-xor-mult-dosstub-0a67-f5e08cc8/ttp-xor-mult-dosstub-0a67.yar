rule TTP_XOR_MULT_DOSStub_0a67 {
  strings:
    $key_0a67 = { 5e 0f [2] 2a 17 [2] 6d 15 [2] 2a 04 [2] 64 08 [2] 68 02 [2] 7f 09 [2] 64 47 [2] 59 }

  condition:
    any of them
}