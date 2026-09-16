rule TTP_XOR_MULT_DOSStub_29f9 {
  strings:
    $key_29f9 = { 7d 91 [2] 09 89 [2] 4e 8b [2] 09 9a [2] 47 96 [2] 4b 9c [2] 5c 97 [2] 47 d9 [2] 7a }

  condition:
    any of them
}