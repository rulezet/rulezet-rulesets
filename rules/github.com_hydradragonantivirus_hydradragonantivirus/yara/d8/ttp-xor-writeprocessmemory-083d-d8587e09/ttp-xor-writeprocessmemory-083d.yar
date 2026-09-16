rule TTP_XOR_WriteProcessMemory_083d {
  strings:
    $key_083d = { 5f 4f [2] 6d 6d [2] 6b 58 [2] 45 58 [2] 7a 44 }

  condition:
    any of them
}