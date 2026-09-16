rule TTP_XOR_MULT_DOSStub_2921 {
  strings:
    $key_2921 = { 7d 49 [2] 09 51 [2] 4e 53 [2] 09 42 [2] 47 4e [2] 4b 44 [2] 5c 4f [2] 47 01 [2] 7a }

  condition:
    any of them
}