rule TTP_XOR_MULT_DOSStub_106a {
  strings:
    $key_106a = { 44 02 [2] 30 1a [2] 77 18 [2] 30 09 [2] 7e 05 [2] 72 0f [2] 65 04 [2] 7e 4a [2] 43 }

  condition:
    any of them
}