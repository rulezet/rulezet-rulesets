rule TTP_XOR_MULT_DOSStub_88cd {
  strings:
    $key_88cd = { dc a5 [2] a8 bd [2] ef bf [2] a8 ae [2] e6 a2 [2] ea a8 [2] fd a3 [2] e6 ed [2] db }

  condition:
    any of them
}