rule TTP_XOR_MULT_DOSStub_0a7c {
  strings:
    $key_0a7c = { 5e 14 [2] 2a 0c [2] 6d 0e [2] 2a 1f [2] 64 13 [2] 68 19 [2] 7f 12 [2] 64 5c [2] 59 }

  condition:
    any of them
}