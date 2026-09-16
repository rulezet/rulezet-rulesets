rule TTP_XOR_WriteProcessMemory_34dc {
  strings:
    $key_34dc = { 63 ae [2] 51 8c [2] 57 b9 [2] 79 b9 [2] 46 a5 }

  condition:
    any of them
}