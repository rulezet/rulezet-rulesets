rule TTP_XOR_MULT_DOSStub_3b3c {
  strings:
    $key_3b3c = { 6f 54 [2] 1b 4c [2] 5c 4e [2] 1b 5f [2] 55 53 [2] 59 59 [2] 4e 52 [2] 55 1c [2] 68 }

  condition:
    any of them
}