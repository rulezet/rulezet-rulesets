rule TTP_XOR_MULT_DOSStub_7f29 {
  strings:
    $key_7f29 = { 2b 41 [2] 5f 59 [2] 18 5b [2] 5f 4a [2] 11 46 [2] 1d 4c [2] 0a 47 [2] 11 09 [2] 2c }

  condition:
    any of them
}