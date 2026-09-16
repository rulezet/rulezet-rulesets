rule TTP_XOR_MULT_DOSStub_ffe5 {
  strings:
    $key_ffe5 = { ab 8d [2] df 95 [2] 98 97 [2] df 86 [2] 91 8a [2] 9d 80 [2] 8a 8b [2] 91 c5 [2] ac }

  condition:
    any of them
}