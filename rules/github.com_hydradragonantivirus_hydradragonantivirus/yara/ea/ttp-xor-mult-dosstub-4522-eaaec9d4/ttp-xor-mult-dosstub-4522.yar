rule TTP_XOR_MULT_DOSStub_4522 {
  strings:
    $key_4522 = { 11 4a [2] 65 52 [2] 22 50 [2] 65 41 [2] 2b 4d [2] 27 47 [2] 30 4c [2] 2b 02 [2] 16 }

  condition:
    any of them
}