rule TTP_XOR_MULT_DOSStub_ff1b {
  strings:
    $key_ff1b = { ab 73 [2] df 6b [2] 98 69 [2] df 78 [2] 91 74 [2] 9d 7e [2] 8a 75 [2] 91 3b [2] ac }

  condition:
    any of them
}