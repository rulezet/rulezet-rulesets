rule TTP_XOR_WriteProcessMemory_3ec7 {
  strings:
    $key_3ec7 = { 69 b5 [2] 5b 97 [2] 5d a2 [2] 73 a2 [2] 4c be }

  condition:
    any of them
}