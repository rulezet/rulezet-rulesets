rule TTP_XOR_MULT_DOSStub_19cd {
  strings:
    $key_19cd = { 4d a5 [2] 39 bd [2] 7e bf [2] 39 ae [2] 77 a2 [2] 7b a8 [2] 6c a3 [2] 77 ed [2] 4a }

  condition:
    any of them
}