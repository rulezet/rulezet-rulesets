rule TTP_XOR_WriteProcessMemory_18ce {
  strings:
    $key_18ce = { 4f bc [2] 7d 9e [2] 7b ab [2] 55 ab [2] 6a b7 }

  condition:
    any of them
}