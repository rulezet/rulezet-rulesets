rule TTP_XOR_WriteProcessMemory_13dc {
  strings:
    $key_13dc = { 44 ae [2] 76 8c [2] 70 b9 [2] 5e b9 [2] 61 a5 }

  condition:
    any of them
}