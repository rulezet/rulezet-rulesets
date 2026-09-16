rule TTP_XOR_MULT_DOSStub_7f64 {
  strings:
    $key_7f64 = { 2b 0c [2] 5f 14 [2] 18 16 [2] 5f 07 [2] 11 0b [2] 1d 01 [2] 0a 0a [2] 11 44 [2] 2c }

  condition:
    any of them
}