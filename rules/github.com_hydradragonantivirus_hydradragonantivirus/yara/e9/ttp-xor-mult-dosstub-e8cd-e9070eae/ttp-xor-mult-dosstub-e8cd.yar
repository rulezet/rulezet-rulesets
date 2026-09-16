rule TTP_XOR_MULT_DOSStub_e8cd {
  strings:
    $key_e8cd = { bc a5 [2] c8 bd [2] 8f bf [2] c8 ae [2] 86 a2 [2] 8a a8 [2] 9d a3 [2] 86 ed [2] bb }

  condition:
    any of them
}