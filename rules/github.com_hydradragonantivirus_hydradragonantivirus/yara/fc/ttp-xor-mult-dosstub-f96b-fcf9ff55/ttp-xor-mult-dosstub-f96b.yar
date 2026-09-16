rule TTP_XOR_MULT_DOSStub_f96b {
  strings:
    $key_f96b = { ad 03 [2] d9 1b [2] 9e 19 [2] d9 08 [2] 97 04 [2] 9b 0e [2] 8c 05 [2] 97 4b [2] aa }

  condition:
    any of them
}