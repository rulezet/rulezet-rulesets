rule TTP_XOR_MULT_DOSStub_ff25 {
  strings:
    $key_ff25 = { ab 4d [2] df 55 [2] 98 57 [2] df 46 [2] 91 4a [2] 9d 40 [2] 8a 4b [2] 91 05 [2] ac }

  condition:
    any of them
}