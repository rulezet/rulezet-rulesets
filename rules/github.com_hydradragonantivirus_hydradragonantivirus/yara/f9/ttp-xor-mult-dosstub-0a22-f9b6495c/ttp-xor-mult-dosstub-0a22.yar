rule TTP_XOR_MULT_DOSStub_0a22 {
  strings:
    $key_0a22 = { 5e 4a [2] 2a 52 [2] 6d 50 [2] 2a 41 [2] 64 4d [2] 68 47 [2] 7f 4c [2] 64 02 [2] 59 }

  condition:
    any of them
}