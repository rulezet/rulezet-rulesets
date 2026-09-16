rule TTP_XOR_MULT_DOSStub_cdae {
  strings:
    $key_cdae = { 99 c6 [2] ed de [2] aa dc [2] ed cd [2] a3 c1 [2] af cb [2] b8 c0 [2] a3 8e [2] 9e }

  condition:
    any of them
}