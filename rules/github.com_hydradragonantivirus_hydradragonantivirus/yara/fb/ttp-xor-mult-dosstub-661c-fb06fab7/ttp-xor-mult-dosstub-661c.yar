rule TTP_XOR_MULT_DOSStub_661c {
  strings:
    $key_661c = { 32 74 [2] 46 6c [2] 01 6e [2] 46 7f [2] 08 73 [2] 04 79 [2] 13 72 [2] 08 3c [2] 35 }

  condition:
    any of them
}