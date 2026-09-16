rule TTP_XOR_MULT_DOSStub_ff7b {
  strings:
    $key_ff7b = { ab 13 [2] df 0b [2] 98 09 [2] df 18 [2] 91 14 [2] 9d 1e [2] 8a 15 [2] 91 5b [2] ac }

  condition:
    any of them
}