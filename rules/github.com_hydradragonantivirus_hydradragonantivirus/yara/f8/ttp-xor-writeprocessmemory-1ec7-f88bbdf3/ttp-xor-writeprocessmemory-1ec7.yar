rule TTP_XOR_WriteProcessMemory_1ec7 {
  strings:
    $key_1ec7 = { 49 b5 [2] 7b 97 [2] 7d a2 [2] 53 a2 [2] 6c be }

  condition:
    any of them
}