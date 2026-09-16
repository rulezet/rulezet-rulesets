rule TTP_XOR_MULT_DOSStub_6eff {
  strings:
    $key_6eff = { 3a 97 [2] 4e 8f [2] 09 8d [2] 4e 9c [2] 00 90 [2] 0c 9a [2] 1b 91 [2] 00 df [2] 3d }

  condition:
    any of them
}