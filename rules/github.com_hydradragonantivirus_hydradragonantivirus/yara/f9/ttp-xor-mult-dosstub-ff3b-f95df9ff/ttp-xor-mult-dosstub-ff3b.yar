rule TTP_XOR_MULT_DOSStub_ff3b {
  strings:
    $key_ff3b = { ab 53 [2] df 4b [2] 98 49 [2] df 58 [2] 91 54 [2] 9d 5e [2] 8a 55 [2] 91 1b [2] ac }

  condition:
    any of them
}