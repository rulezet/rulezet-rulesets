rule TTP_XOR_MULT_DOSStub_ff5f {
  strings:
    $key_ff5f = { ab 37 [2] df 2f [2] 98 2d [2] df 3c [2] 91 30 [2] 9d 3a [2] 8a 31 [2] 91 7f [2] ac }

  condition:
    any of them
}