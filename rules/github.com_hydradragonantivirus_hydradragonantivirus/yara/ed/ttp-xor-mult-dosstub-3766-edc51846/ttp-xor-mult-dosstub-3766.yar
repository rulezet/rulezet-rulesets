rule TTP_XOR_MULT_DOSStub_3766 {
  strings:
    $key_3766 = { 63 0e [2] 17 16 [2] 50 14 [2] 17 05 [2] 59 09 [2] 55 03 [2] 42 08 [2] 59 46 [2] 64 }

  condition:
    any of them
}