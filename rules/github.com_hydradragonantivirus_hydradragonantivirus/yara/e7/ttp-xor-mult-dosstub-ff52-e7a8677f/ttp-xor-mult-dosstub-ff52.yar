rule TTP_XOR_MULT_DOSStub_ff52 {
  strings:
    $key_ff52 = { ab 3a [2] df 22 [2] 98 20 [2] df 31 [2] 91 3d [2] 9d 37 [2] 8a 3c [2] 91 72 [2] ac }

  condition:
    any of them
}