rule TTP_XOR_MULT_DOSStub_ff2e {
  strings:
    $key_ff2e = { ab 46 [2] df 5e [2] 98 5c [2] df 4d [2] 91 41 [2] 9d 4b [2] 8a 40 [2] 91 0e [2] ac }

  condition:
    any of them
}