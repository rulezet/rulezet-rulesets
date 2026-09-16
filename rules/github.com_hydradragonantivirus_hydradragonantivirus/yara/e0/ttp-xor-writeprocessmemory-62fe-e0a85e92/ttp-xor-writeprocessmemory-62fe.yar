rule TTP_XOR_WriteProcessMemory_62fe {
  strings:
    $key_62fe = { 35 8c [2] 07 ae [2] 01 9b [2] 2f 9b [2] 10 87 }

  condition:
    any of them
}