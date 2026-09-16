rule TTP_XOR_MULT_DOSStub_62ff {
  strings:
    $key_62ff = { 36 97 [2] 42 8f [2] 05 8d [2] 42 9c [2] 0c 90 [2] 00 9a [2] 17 91 [2] 0c df [2] 31 }

  condition:
    any of them
}