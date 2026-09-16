rule TTP_XOR_MULT_DOSStub_ffd8 {
  strings:
    $key_ffd8 = { ab b0 [2] df a8 [2] 98 aa [2] df bb [2] 91 b7 [2] 9d bd [2] 8a b6 [2] 91 f8 [2] ac }

  condition:
    any of them
}