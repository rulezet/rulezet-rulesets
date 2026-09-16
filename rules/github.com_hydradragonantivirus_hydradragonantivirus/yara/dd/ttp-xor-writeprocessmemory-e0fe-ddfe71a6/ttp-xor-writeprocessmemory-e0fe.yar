rule TTP_XOR_WriteProcessMemory_e0fe {
  strings:
    $key_e0fe = { b7 8c [2] 85 ae [2] 83 9b [2] ad 9b [2] 92 87 }

  condition:
    any of them
}