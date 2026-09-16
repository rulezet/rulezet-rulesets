rule TTP_XOR_WriteProcessMemory_302d {
  strings:
    $key_302d = { 67 5f [2] 55 7d [2] 53 48 [2] 7d 48 [2] 42 54 }

  condition:
    any of them
}