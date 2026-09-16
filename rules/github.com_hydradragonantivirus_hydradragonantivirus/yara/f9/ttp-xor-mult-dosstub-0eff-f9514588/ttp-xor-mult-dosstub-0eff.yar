rule TTP_XOR_MULT_DOSStub_0eff {
  strings:
    $key_0eff = { 5a 97 [2] 2e 8f [2] 69 8d [2] 2e 9c [2] 60 90 [2] 6c 9a [2] 7b 91 [2] 60 df [2] 5d }

  condition:
    any of them
}