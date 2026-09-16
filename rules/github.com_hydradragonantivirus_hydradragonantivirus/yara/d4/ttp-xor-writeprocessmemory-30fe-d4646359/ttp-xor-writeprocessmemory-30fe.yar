rule TTP_XOR_WriteProcessMemory_30fe {
  strings:
    $key_30fe = { 67 8c [2] 55 ae [2] 53 9b [2] 7d 9b [2] 42 87 }

  condition:
    any of them
}