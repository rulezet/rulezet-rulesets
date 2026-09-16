rule TTP_XOR_WriteProcessMemory_64fe {
  strings:
    $key_64fe = { 33 8c [2] 01 ae [2] 07 9b [2] 29 9b [2] 16 87 }

  condition:
    any of them
}