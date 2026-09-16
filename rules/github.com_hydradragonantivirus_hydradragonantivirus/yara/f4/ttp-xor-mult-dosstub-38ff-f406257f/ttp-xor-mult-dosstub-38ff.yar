rule TTP_XOR_MULT_DOSStub_38ff {
  strings:
    $key_38ff = { 6c 97 [2] 18 8f [2] 5f 8d [2] 18 9c [2] 56 90 [2] 5a 9a [2] 4d 91 [2] 56 df [2] 6b }

  condition:
    any of them
}