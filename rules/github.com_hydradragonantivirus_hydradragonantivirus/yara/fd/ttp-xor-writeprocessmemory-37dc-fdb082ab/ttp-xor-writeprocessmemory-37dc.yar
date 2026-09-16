rule TTP_XOR_WriteProcessMemory_37dc {
  strings:
    $key_37dc = { 60 ae [2] 52 8c [2] 54 b9 [2] 7a b9 [2] 45 a5 }

  condition:
    any of them
}