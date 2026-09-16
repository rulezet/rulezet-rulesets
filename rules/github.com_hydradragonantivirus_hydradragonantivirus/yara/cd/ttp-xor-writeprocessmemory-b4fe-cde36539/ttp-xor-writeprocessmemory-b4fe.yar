rule TTP_XOR_WriteProcessMemory_b4fe {
  strings:
    $key_b4fe = { e3 8c [2] d1 ae [2] d7 9b [2] f9 9b [2] c6 87 }

  condition:
    any of them
}