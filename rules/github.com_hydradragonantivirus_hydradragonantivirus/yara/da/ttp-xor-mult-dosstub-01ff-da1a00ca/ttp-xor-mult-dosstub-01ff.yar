rule TTP_XOR_MULT_DOSStub_01ff {
  strings:
    $key_01ff = { 55 97 [2] 21 8f [2] 66 8d [2] 21 9c [2] 6f 90 [2] 63 9a [2] 74 91 [2] 6f df [2] 52 }

  condition:
    any of them
}