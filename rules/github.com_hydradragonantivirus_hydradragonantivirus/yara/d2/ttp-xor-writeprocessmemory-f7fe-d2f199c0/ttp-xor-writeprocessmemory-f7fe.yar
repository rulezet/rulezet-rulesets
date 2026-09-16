rule TTP_XOR_WriteProcessMemory_f7fe {
  strings:
    $key_f7fe = { a0 8c [2] 92 ae [2] 94 9b [2] ba 9b [2] 85 87 }

  condition:
    any of them
}