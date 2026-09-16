rule TTP_XOR_WriteProcessMemory_5845 {
  strings:
    $key_5845 = { 0f 37 [2] 3d 15 [2] 3b 20 [2] 15 20 [2] 2a 3c }

  condition:
    any of them
}