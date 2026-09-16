rule TTP_XOR_WriteProcessMemory_d4fe {
  strings:
    $key_d4fe = { 83 8c [2] b1 ae [2] b7 9b [2] 99 9b [2] a6 87 }

  condition:
    any of them
}