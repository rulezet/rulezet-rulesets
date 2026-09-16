rule TTP_XOR_MULT_DOSStub_ff15 {
  strings:
    $key_ff15 = { ab 7d [2] df 65 [2] 98 67 [2] df 76 [2] 91 7a [2] 9d 70 [2] 8a 7b [2] 91 35 [2] ac }

  condition:
    any of them
}