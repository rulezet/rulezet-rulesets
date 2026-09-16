rule TTP_XOR_MULT_DOSStub_19f4 {
  strings:
    $key_19f4 = { 4d 9c [2] 39 84 [2] 7e 86 [2] 39 97 [2] 77 9b [2] 7b 91 [2] 6c 9a [2] 77 d4 [2] 4a }

  condition:
    any of them
}