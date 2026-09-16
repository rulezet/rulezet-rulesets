rule TTP_XOR_MULT_DOSStub_fff8 {
  strings:
    $key_fff8 = { ab 90 [2] df 88 [2] 98 8a [2] df 9b [2] 91 97 [2] 9d 9d [2] 8a 96 [2] 91 d8 [2] ac }

  condition:
    any of them
}