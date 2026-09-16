rule TTP_XOR_WriteProcessMemory_5dcd {
  strings:
    $key_5dcd = { 0a bf [2] 38 9d [2] 3e a8 [2] 10 a8 [2] 2f b4 }

  condition:
    any of them
}