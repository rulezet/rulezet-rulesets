rule TTP_XOR_MULT_DOSStub_ff07 {
  strings:
    $key_ff07 = { ab 6f [2] df 77 [2] 98 75 [2] df 64 [2] 91 68 [2] 9d 62 [2] 8a 69 [2] 91 27 [2] ac }

  condition:
    any of them
}