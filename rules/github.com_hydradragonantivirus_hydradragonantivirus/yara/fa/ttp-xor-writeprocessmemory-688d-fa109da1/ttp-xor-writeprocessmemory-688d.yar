rule TTP_XOR_WriteProcessMemory_688d {
  strings:
    $key_688d = { 3f ff [2] 0d dd [2] 0b e8 [2] 25 e8 [2] 1a f4 }

  condition:
    any of them
}