rule TTP_XOR_WriteProcessMemory_f5fe {
  strings:
    $key_f5fe = { a2 8c [2] 90 ae [2] 96 9b [2] b8 9b [2] 87 87 }

  condition:
    any of them
}