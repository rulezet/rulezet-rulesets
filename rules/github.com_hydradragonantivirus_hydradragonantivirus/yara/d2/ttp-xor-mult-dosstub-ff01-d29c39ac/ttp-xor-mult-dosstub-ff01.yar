rule TTP_XOR_MULT_DOSStub_ff01 {
  strings:
    $key_ff01 = { ab 69 [2] df 71 [2] 98 73 [2] df 62 [2] 91 6e [2] 9d 64 [2] 8a 6f [2] 91 21 [2] ac }

  condition:
    any of them
}