rule TTP_XOR_MULT_DOSStub_290c {
  strings:
    $key_290c = { 7d 64 [2] 09 7c [2] 4e 7e [2] 09 6f [2] 47 63 [2] 4b 69 [2] 5c 62 [2] 47 2c [2] 7a }

  condition:
    any of them
}