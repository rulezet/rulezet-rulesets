rule TTP_XOR_MULT_DOSStub_29fa {
  strings:
    $key_29fa = { 7d 92 [2] 09 8a [2] 4e 88 [2] 09 99 [2] 47 95 [2] 4b 9f [2] 5c 94 [2] 47 da [2] 7a }

  condition:
    any of them
}