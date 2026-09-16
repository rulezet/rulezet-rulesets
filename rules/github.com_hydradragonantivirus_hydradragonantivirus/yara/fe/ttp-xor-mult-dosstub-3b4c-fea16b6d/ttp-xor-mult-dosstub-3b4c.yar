rule TTP_XOR_MULT_DOSStub_3b4c {
  strings:
    $key_3b4c = { 6f 24 [2] 1b 3c [2] 5c 3e [2] 1b 2f [2] 55 23 [2] 59 29 [2] 4e 22 [2] 55 6c [2] 68 }

  condition:
    any of them
}