rule TTP_XOR_WriteProcessMemory_51dc {
  strings:
    $key_51dc = { 06 ae [2] 34 8c [2] 32 b9 [2] 1c b9 [2] 23 a5 }

  condition:
    any of them
}