rule TTP_XOR_MULT_DOSStub_986c {
  strings:
    $key_986c = { cc 04 [2] b8 1c [2] ff 1e [2] b8 0f [2] f6 03 [2] fa 09 [2] ed 02 [2] f6 4c [2] cb }

  condition:
    any of them
}