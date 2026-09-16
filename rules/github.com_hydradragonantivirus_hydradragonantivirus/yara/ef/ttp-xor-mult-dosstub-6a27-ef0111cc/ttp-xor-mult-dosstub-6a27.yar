rule TTP_XOR_MULT_DOSStub_6a27 {
  strings:
    $key_6a27 = { 3e 4f [2] 4a 57 [2] 0d 55 [2] 4a 44 [2] 04 48 [2] 08 42 [2] 1f 49 [2] 04 07 [2] 39 }

  condition:
    any of them
}