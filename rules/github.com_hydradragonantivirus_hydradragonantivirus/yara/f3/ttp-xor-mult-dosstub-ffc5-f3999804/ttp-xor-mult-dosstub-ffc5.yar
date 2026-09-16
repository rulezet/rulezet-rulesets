rule TTP_XOR_MULT_DOSStub_ffc5 {
  strings:
    $key_ffc5 = { ab ad [2] df b5 [2] 98 b7 [2] df a6 [2] 91 aa [2] 9d a0 [2] 8a ab [2] 91 e5 [2] ac }

  condition:
    any of them
}