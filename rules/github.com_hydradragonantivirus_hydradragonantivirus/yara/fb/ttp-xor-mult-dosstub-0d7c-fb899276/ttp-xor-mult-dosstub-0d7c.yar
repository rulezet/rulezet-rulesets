rule TTP_XOR_MULT_DOSStub_0d7c {
  strings:
    $key_0d7c = { 59 14 [2] 2d 0c [2] 6a 0e [2] 2d 1f [2] 63 13 [2] 6f 19 [2] 78 12 [2] 63 5c [2] 5e }

  condition:
    any of them
}