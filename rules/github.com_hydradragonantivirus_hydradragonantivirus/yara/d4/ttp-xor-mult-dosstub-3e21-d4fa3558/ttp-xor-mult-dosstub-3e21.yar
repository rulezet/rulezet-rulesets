rule TTP_XOR_MULT_DOSStub_3e21 {
  strings:
    $key_3e21 = { 6a 49 [2] 1e 51 [2] 59 53 [2] 1e 42 [2] 50 4e [2] 5c 44 [2] 4b 4f [2] 50 01 [2] 6d }

  condition:
    any of them
}