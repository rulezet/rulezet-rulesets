rule TTP_XOR_WriteProcessMemory_73fe {
  strings:
    $key_73fe = { 24 8c [2] 16 ae [2] 10 9b [2] 3e 9b [2] 01 87 }

  condition:
    any of them
}