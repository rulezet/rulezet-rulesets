rule TTP_XOR_MULT_DOSStub_670c {
  strings:
    $key_670c = { 33 64 [2] 47 7c [2] 00 7e [2] 47 6f [2] 09 63 [2] 05 69 [2] 12 62 [2] 09 2c [2] 34 }

  condition:
    any of them
}