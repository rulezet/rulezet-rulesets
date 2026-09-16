rule TTP_XOR_WriteProcessMemory_3ef2 {
  strings:
    $key_3ef2 = { 69 80 [2] 5b a2 [2] 5d 97 [2] 73 97 [2] 4c 8b }

  condition:
    any of them
}