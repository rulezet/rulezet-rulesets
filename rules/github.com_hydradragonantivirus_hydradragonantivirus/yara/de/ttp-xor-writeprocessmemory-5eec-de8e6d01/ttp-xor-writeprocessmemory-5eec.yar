rule TTP_XOR_WriteProcessMemory_5eec {
  strings:
    $key_5eec = { 09 9e [2] 3b bc [2] 3d 89 [2] 13 89 [2] 2c 95 }

  condition:
    any of them
}