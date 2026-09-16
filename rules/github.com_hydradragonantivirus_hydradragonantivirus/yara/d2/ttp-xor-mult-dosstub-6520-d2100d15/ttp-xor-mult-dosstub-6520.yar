rule TTP_XOR_MULT_DOSStub_6520 {
  strings:
    $key_6520 = { 31 48 [2] 45 50 [2] 02 52 [2] 45 43 [2] 0b 4f [2] 07 45 [2] 10 4e [2] 0b 00 [2] 36 }

  condition:
    any of them
}