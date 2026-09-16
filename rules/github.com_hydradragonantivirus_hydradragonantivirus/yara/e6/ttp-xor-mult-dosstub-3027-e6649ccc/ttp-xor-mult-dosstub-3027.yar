rule TTP_XOR_MULT_DOSStub_3027 {
  strings:
    $key_3027 = { 64 4f [2] 10 57 [2] 57 55 [2] 10 44 [2] 5e 48 [2] 52 42 [2] 45 49 [2] 5e 07 [2] 63 }

  condition:
    any of them
}