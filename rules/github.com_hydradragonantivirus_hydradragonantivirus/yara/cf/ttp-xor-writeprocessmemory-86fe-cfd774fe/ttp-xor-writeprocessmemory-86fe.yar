rule TTP_XOR_WriteProcessMemory_86fe {
  strings:
    $key_86fe = { d1 8c [2] e3 ae [2] e5 9b [2] cb 9b [2] f4 87 }

  condition:
    any of them
}