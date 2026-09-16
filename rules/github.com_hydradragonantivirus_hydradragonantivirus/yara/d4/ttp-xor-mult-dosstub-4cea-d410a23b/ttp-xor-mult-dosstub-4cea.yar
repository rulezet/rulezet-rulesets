rule TTP_XOR_MULT_DOSStub_4cea {
  strings:
    $key_4cea = { 18 82 [2] 6c 9a [2] 2b 98 [2] 6c 89 [2] 22 85 [2] 2e 8f [2] 39 84 [2] 22 ca [2] 1f }

  condition:
    any of them
}