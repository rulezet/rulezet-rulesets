rule TTP_XOR_MULT_DOSStub_ff4d {
  strings:
    $key_ff4d = { ab 25 [2] df 3d [2] 98 3f [2] df 2e [2] 91 22 [2] 9d 28 [2] 8a 23 [2] 91 6d [2] ac }

  condition:
    any of them
}