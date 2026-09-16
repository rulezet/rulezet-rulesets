rule TTP_XOR_MULT_DOSStub_18ff {
  strings:
    $key_18ff = { 4c 97 [2] 38 8f [2] 7f 8d [2] 38 9c [2] 76 90 [2] 7a 9a [2] 6d 91 [2] 76 df [2] 4b }

  condition:
    any of them
}