rule TTP_XOR_WriteProcessMemory_31fe {
  strings:
    $key_31fe = { 66 8c [2] 54 ae [2] 52 9b [2] 7c 9b [2] 43 87 }

  condition:
    any of them
}