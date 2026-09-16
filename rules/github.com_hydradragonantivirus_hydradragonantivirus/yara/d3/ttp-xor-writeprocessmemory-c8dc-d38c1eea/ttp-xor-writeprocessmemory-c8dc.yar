rule TTP_XOR_WriteProcessMemory_c8dc {
  strings:
    $key_c8dc = { 9f ae [2] ad 8c [2] ab b9 [2] 85 b9 [2] ba a5 }

  condition:
    any of them
}