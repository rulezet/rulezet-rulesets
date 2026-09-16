rule TTP_XOR_MULT_DOSStub_0eea {
  strings:
    $key_0eea = { 5a 82 [2] 2e 9a [2] 69 98 [2] 2e 89 [2] 60 85 [2] 6c 8f [2] 7b 84 [2] 60 ca [2] 5d }

  condition:
    any of them
}