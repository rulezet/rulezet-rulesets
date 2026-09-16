rule TTP_XOR_MULT_DOSStub_cced {
  strings:
    $key_cced = { 98 85 [2] ec 9d [2] ab 9f [2] ec 8e [2] a2 82 [2] ae 88 [2] b9 83 [2] a2 cd [2] 9f }

  condition:
    any of them
}