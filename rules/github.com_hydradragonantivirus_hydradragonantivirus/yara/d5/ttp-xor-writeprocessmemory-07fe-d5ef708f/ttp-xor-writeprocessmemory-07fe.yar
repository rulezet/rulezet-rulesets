rule TTP_XOR_WriteProcessMemory_07fe {
  strings:
    $key_07fe = { 50 8c [2] 62 ae [2] 64 9b [2] 4a 9b [2] 75 87 }

  condition:
    any of them
}