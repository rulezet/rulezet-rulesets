rule TTP_XOR_WriteProcessMemory_accc {
  strings:
    $key_accc = { fb be [2] c9 9c [2] cf a9 [2] e1 a9 [2] de b5 }

  condition:
    any of them
}