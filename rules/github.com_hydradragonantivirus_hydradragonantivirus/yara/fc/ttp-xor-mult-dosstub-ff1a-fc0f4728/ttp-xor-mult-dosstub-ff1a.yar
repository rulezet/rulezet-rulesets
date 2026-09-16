rule TTP_XOR_MULT_DOSStub_ff1a {
  strings:
    $key_ff1a = { ab 72 [2] df 6a [2] 98 68 [2] df 79 [2] 91 75 [2] 9d 7f [2] 8a 74 [2] 91 3a [2] ac }

  condition:
    any of them
}