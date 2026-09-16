rule TTP_XOR_MULT_DOSStub_6a67 {
  strings:
    $key_6a67 = { 3e 0f [2] 4a 17 [2] 0d 15 [2] 4a 04 [2] 04 08 [2] 08 02 [2] 1f 09 [2] 04 47 [2] 39 }

  condition:
    any of them
}