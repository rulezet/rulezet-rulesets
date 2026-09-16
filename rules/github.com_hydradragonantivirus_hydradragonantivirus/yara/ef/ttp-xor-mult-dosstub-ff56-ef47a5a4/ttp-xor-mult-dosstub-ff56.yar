rule TTP_XOR_MULT_DOSStub_ff56 {
  strings:
    $key_ff56 = { ab 3e [2] df 26 [2] 98 24 [2] df 35 [2] 91 39 [2] 9d 33 [2] 8a 38 [2] 91 76 [2] ac }

  condition:
    any of them
}