rule TTP_XOR_MULT_DOSStub_a8cd {
  strings:
    $key_a8cd = { fc a5 [2] 88 bd [2] cf bf [2] 88 ae [2] c6 a2 [2] ca a8 [2] dd a3 [2] c6 ed [2] fb }

  condition:
    any of them
}