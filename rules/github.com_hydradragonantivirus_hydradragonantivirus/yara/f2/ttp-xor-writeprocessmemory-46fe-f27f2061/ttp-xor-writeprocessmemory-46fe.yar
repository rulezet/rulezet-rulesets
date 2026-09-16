rule TTP_XOR_WriteProcessMemory_46fe {
  strings:
    $key_46fe = { 11 8c [2] 23 ae [2] 25 9b [2] 0b 9b [2] 34 87 }

  condition:
    any of them
}