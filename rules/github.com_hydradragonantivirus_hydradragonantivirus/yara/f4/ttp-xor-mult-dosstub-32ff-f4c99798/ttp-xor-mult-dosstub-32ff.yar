rule TTP_XOR_MULT_DOSStub_32ff {
  strings:
    $key_32ff = { 66 97 [2] 12 8f [2] 55 8d [2] 12 9c [2] 5c 90 [2] 50 9a [2] 47 91 [2] 5c df [2] 61 }

  condition:
    any of them
}