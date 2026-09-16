rule TTP_XOR_MULT_DOSStub_096a {
  strings:
    $key_096a = { 5d 02 [2] 29 1a [2] 6e 18 [2] 29 09 [2] 67 05 [2] 6b 0f [2] 7c 04 [2] 67 4a [2] 5a }

  condition:
    any of them
}