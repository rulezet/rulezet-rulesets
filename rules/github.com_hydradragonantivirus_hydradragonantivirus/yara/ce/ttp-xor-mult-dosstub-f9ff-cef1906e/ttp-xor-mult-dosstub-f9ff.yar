rule TTP_XOR_MULT_DOSStub_f9ff {
  strings:
    $key_f9ff = { ad 97 [2] d9 8f [2] 9e 8d [2] d9 9c [2] 97 90 [2] 9b 9a [2] 8c 91 [2] 97 df [2] aa }

  condition:
    any of them
}