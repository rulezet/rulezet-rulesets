rule TTP_XOR_MULT_DOSStub_ffed {
  strings:
    $key_ffed = { ab 85 [2] df 9d [2] 98 9f [2] df 8e [2] 91 82 [2] 9d 88 [2] 8a 83 [2] 91 cd [2] ac }

  condition:
    any of them
}