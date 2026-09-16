rule TTP_XOR_MULT_DOSStub_fffd {
  strings:
    $key_fffd = { ab 95 [2] df 8d [2] 98 8f [2] df 9e [2] 91 92 [2] 9d 98 [2] 8a 93 [2] 91 dd [2] ac }

  condition:
    any of them
}