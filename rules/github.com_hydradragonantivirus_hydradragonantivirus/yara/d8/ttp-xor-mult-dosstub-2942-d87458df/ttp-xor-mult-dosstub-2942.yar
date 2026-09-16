rule TTP_XOR_MULT_DOSStub_2942 {
  strings:
    $key_2942 = { 7d 2a [2] 09 32 [2] 4e 30 [2] 09 21 [2] 47 2d [2] 4b 27 [2] 5c 2c [2] 47 62 [2] 7a }

  condition:
    any of them
}