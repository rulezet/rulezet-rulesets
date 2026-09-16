rule TTP_XOR_MULT_DOSStub_ff31 {
  strings:
    $key_ff31 = { ab 59 [2] df 41 [2] 98 43 [2] df 52 [2] 91 5e [2] 9d 54 [2] 8a 5f [2] 91 11 [2] ac }

  condition:
    any of them
}