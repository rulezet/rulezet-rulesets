rule TTP_XOR_MULT_DOSStub_4eff {
  strings:
    $key_4eff = { 1a 97 [2] 6e 8f [2] 29 8d [2] 6e 9c [2] 20 90 [2] 2c 9a [2] 3b 91 [2] 20 df [2] 1d }

  condition:
    any of them
}