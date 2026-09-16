rule TTP_XOR_MULT_DOSStub_ff61 {
  strings:
    $key_ff61 = { ab 09 [2] df 11 [2] 98 13 [2] df 02 [2] 91 0e [2] 9d 04 [2] 8a 0f [2] 91 41 [2] ac }

  condition:
    any of them
}