rule TTP_XOR_MULT_DOSStub_195a {
  strings:
    $key_195a = { 4d 32 [2] 39 2a [2] 7e 28 [2] 39 39 [2] 77 35 [2] 7b 3f [2] 6c 34 [2] 77 7a [2] 4a }

  condition:
    any of them
}