rule TTP_XOR_WriteProcessMemory_e7dc {
  strings:
    $key_e7dc = { b0 ae [2] 82 8c [2] 84 b9 [2] aa b9 [2] 95 a5 }

  condition:
    any of them
}