rule TTP_XOR_MULT_DOSStub_ffae {
  strings:
    $key_ffae = { ab c6 [2] df de [2] 98 dc [2] df cd [2] 91 c1 [2] 9d cb [2] 8a c0 [2] 91 8e [2] ac }

  condition:
    any of them
}