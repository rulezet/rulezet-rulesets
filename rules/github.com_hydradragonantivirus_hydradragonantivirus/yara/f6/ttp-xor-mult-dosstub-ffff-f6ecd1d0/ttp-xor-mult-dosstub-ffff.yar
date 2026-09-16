rule TTP_XOR_MULT_DOSStub_ffff {
  strings:
    $key_ffff = { ab 97 [2] df 8f [2] 98 8d [2] df 9c [2] 91 90 [2] 9d 9a [2] 8a 91 [2] 91 df [2] ac }

  condition:
    any of them
}