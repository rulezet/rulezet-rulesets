rule TTP_XOR_MULT_DOSStub_f923 {
  strings:
    $key_f923 = { ad 4b [2] d9 53 [2] 9e 51 [2] d9 40 [2] 97 4c [2] 9b 46 [2] 8c 4d [2] 97 03 [2] aa }

  condition:
    any of them
}