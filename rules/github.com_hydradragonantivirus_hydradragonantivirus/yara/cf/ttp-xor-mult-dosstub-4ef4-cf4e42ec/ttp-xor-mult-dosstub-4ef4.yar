rule TTP_XOR_MULT_DOSStub_4ef4 {
  strings:
    $key_4ef4 = { 1a 9c [2] 6e 84 [2] 29 86 [2] 6e 97 [2] 20 9b [2] 2c 91 [2] 3b 9a [2] 20 d4 [2] 1d }

  condition:
    any of them
}