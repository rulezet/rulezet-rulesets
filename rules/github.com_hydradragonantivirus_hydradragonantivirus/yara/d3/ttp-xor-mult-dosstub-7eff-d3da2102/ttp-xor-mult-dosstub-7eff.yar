rule TTP_XOR_MULT_DOSStub_7eff {
  strings:
    $key_7eff = { 2a 97 [2] 5e 8f [2] 19 8d [2] 5e 9c [2] 10 90 [2] 1c 9a [2] 0b 91 [2] 10 df [2] 2d }

  condition:
    any of them
}