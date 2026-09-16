rule TTP_XOR_MULT_DOSStub_6f6a {
  strings:
    $key_6f6a = { 3b 02 [2] 4f 1a [2] 08 18 [2] 4f 09 [2] 01 05 [2] 0d 0f [2] 1a 04 [2] 01 4a [2] 3c }

  condition:
    any of them
}