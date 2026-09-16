rule TTP_XOR_MULT_DOSStub_5e22 {
  strings:
    $key_5e22 = { 0a 4a [2] 7e 52 [2] 39 50 [2] 7e 41 [2] 30 4d [2] 3c 47 [2] 2b 4c [2] 30 02 [2] 0d }

  condition:
    any of them
}