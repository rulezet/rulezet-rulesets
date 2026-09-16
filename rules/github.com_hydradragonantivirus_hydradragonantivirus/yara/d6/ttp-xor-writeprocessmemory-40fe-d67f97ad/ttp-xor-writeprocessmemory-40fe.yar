rule TTP_XOR_WriteProcessMemory_40fe {
  strings:
    $key_40fe = { 17 8c [2] 25 ae [2] 23 9b [2] 0d 9b [2] 32 87 }

  condition:
    any of them
}