rule TTP_XOR_WriteProcessMemory_31dc {
  strings:
    $key_31dc = { 66 ae [2] 54 8c [2] 52 b9 [2] 7c b9 [2] 43 a5 }

  condition:
    any of them
}