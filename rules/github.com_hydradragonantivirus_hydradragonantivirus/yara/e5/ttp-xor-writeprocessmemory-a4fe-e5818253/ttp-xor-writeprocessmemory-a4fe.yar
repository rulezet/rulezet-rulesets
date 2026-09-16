rule TTP_XOR_WriteProcessMemory_a4fe {
  strings:
    $key_a4fe = { f3 8c [2] c1 ae [2] c7 9b [2] e9 9b [2] d6 87 }

  condition:
    any of them
}