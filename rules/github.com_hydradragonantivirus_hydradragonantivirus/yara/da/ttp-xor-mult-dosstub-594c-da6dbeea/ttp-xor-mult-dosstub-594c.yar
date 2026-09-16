rule TTP_XOR_MULT_DOSStub_594c {
  strings:
    $key_594c = { 0d 24 [2] 79 3c [2] 3e 3e [2] 79 2f [2] 37 23 [2] 3b 29 [2] 2c 22 [2] 37 6c [2] 0a }

  condition:
    any of them
}