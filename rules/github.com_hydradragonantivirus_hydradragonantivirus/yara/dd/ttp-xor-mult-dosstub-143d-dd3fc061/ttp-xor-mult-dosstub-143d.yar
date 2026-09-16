rule TTP_XOR_MULT_DOSStub_143d {
  strings:
    $key_143d = { 40 55 [2] 34 4d [2] 73 4f [2] 34 5e [2] 7a 52 [2] 76 58 [2] 61 53 [2] 7a 1d [2] 47 }

  condition:
    any of them
}