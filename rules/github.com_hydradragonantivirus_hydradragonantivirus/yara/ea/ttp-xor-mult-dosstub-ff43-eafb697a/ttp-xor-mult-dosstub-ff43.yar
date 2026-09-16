rule TTP_XOR_MULT_DOSStub_ff43 {
  strings:
    $key_ff43 = { ab 2b [2] df 33 [2] 98 31 [2] df 20 [2] 91 2c [2] 9d 26 [2] 8a 2d [2] 91 63 [2] ac }

  condition:
    any of them
}