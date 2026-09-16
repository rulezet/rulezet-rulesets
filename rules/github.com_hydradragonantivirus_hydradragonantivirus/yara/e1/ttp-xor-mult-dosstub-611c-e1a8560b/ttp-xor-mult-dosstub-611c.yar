rule TTP_XOR_MULT_DOSStub_611c {
  strings:
    $key_611c = { 35 74 [2] 41 6c [2] 06 6e [2] 41 7f [2] 0f 73 [2] 03 79 [2] 14 72 [2] 0f 3c [2] 32 }

  condition:
    any of them
}