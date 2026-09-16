rule TTP_XOR_MULT_DOSStub_ff10 {
  strings:
    $key_ff10 = { ab 78 [2] df 60 [2] 98 62 [2] df 73 [2] 91 7f [2] 9d 75 [2] 8a 7e [2] 91 30 [2] ac }

  condition:
    any of them
}