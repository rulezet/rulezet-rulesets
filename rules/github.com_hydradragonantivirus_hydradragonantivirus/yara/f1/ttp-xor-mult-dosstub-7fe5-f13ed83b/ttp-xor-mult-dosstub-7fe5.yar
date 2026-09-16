rule TTP_XOR_MULT_DOSStub_7fe5 {
  strings:
    $key_7fe5 = { 2b 8d [2] 5f 95 [2] 18 97 [2] 5f 86 [2] 11 8a [2] 1d 80 [2] 0a 8b [2] 11 c5 [2] 2c }

  condition:
    any of them
}