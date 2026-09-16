rule TTP_XOR_WriteProcessMemory_58e5 {
  strings:
    $key_58e5 = { 0f 97 [2] 3d b5 [2] 3b 80 [2] 15 80 [2] 2a 9c }

  condition:
    any of them
}