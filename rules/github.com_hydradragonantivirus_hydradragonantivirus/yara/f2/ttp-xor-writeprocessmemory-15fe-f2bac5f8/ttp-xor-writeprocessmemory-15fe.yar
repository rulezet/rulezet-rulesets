rule TTP_XOR_WriteProcessMemory_15fe {
  strings:
    $key_15fe = { 42 8c [2] 70 ae [2] 76 9b [2] 58 9b [2] 67 87 }

  condition:
    any of them
}