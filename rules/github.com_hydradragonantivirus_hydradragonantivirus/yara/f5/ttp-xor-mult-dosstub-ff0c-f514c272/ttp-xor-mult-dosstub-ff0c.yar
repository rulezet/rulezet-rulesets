rule TTP_XOR_MULT_DOSStub_ff0c {
  strings:
    $key_ff0c = { ab 64 [2] df 7c [2] 98 7e [2] df 6f [2] 91 63 [2] 9d 69 [2] 8a 62 [2] 91 2c [2] ac }

  condition:
    any of them
}