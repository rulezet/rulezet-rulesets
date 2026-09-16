rule TTP_XOR_MULT_DOSStub_ff1e {
  strings:
    $key_ff1e = { ab 76 [2] df 6e [2] 98 6c [2] df 7d [2] 91 71 [2] 9d 7b [2] 8a 70 [2] 91 3e [2] ac }

  condition:
    any of them
}