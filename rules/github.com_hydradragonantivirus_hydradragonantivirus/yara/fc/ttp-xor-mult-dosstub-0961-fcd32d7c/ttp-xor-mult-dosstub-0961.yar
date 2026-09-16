rule TTP_XOR_MULT_DOSStub_0961 {
  strings:
    $key_0961 = { 5d 09 [2] 29 11 [2] 6e 13 [2] 29 02 [2] 67 0e [2] 6b 04 [2] 7c 0f [2] 67 41 [2] 5a }

  condition:
    any of them
}