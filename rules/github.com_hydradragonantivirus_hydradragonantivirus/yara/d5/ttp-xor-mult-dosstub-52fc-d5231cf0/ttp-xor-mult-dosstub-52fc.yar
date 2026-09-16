rule TTP_XOR_MULT_DOSStub_52fc {
  strings:
    $key_52fc = { 06 94 [2] 72 8c [2] 35 8e [2] 72 9f [2] 3c 93 [2] 30 99 [2] 27 92 [2] 3c dc [2] 01 }

  condition:
    any of them
}