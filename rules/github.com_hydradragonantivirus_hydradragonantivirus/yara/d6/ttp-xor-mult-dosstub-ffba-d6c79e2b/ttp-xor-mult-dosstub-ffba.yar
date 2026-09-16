rule TTP_XOR_MULT_DOSStub_ffba {
  strings:
    $key_ffba = { ab d2 [2] df ca [2] 98 c8 [2] df d9 [2] 91 d5 [2] 9d df [2] 8a d4 [2] 91 9a [2] ac }

  condition:
    any of them
}