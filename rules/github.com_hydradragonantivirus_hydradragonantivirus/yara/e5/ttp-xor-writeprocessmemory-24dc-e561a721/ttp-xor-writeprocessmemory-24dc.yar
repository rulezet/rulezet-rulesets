rule TTP_XOR_WriteProcessMemory_24dc {
  strings:
    $key_24dc = { 73 ae [2] 41 8c [2] 47 b9 [2] 69 b9 [2] 56 a5 }

  condition:
    any of them
}