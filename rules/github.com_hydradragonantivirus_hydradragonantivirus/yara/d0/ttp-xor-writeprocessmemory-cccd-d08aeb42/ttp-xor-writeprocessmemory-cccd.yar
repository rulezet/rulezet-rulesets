rule TTP_XOR_WriteProcessMemory_cccd {
  strings:
    $key_cccd = { 9b bf [2] a9 9d [2] af a8 [2] 81 a8 [2] be b4 }

  condition:
    any of them
}