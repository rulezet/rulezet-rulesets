rule TTP_XOR_WriteProcessMemory_04fe {
  strings:
    $key_04fe = { 53 8c [2] 61 ae [2] 67 9b [2] 49 9b [2] 76 87 }

  condition:
    any of them
}