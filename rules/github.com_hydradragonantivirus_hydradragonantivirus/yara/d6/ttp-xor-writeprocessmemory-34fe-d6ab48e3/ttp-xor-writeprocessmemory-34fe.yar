rule TTP_XOR_WriteProcessMemory_34fe {
  strings:
    $key_34fe = { 63 8c [2] 51 ae [2] 57 9b [2] 79 9b [2] 46 87 }

  condition:
    any of them
}