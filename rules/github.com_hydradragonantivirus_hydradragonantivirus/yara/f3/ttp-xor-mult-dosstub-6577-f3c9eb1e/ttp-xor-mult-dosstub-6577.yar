rule TTP_XOR_MULT_DOSStub_6577 {
  strings:
    $key_6577 = { 31 1f [2] 45 07 [2] 02 05 [2] 45 14 [2] 0b 18 [2] 07 12 [2] 10 19 [2] 0b 57 [2] 36 }

  condition:
    any of them
}