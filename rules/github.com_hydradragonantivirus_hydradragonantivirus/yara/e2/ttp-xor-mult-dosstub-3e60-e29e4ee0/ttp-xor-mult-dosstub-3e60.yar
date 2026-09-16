rule TTP_XOR_MULT_DOSStub_3e60 {
  strings:
    $key_3e60 = { 6a 08 [2] 1e 10 [2] 59 12 [2] 1e 03 [2] 50 0f [2] 5c 05 [2] 4b 0e [2] 50 40 [2] 6d }

  condition:
    any of them
}