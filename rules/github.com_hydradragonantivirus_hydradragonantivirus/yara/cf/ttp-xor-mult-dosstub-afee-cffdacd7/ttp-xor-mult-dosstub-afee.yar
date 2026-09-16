rule TTP_XOR_MULT_DOSStub_afee {
  strings:
    $key_afee = { fb 86 [2] 8f 9e [2] c8 9c [2] 8f 8d [2] c1 81 [2] cd 8b [2] da 80 [2] c1 ce [2] fc }

  condition:
    any of them
}