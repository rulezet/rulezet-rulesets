rule TTP_XOR_MULT_DOSStub_ff48 {
  strings:
    $key_ff48 = { ab 20 [2] df 38 [2] 98 3a [2] df 2b [2] 91 27 [2] 9d 2d [2] 8a 26 [2] 91 68 [2] ac }

  condition:
    any of them
}