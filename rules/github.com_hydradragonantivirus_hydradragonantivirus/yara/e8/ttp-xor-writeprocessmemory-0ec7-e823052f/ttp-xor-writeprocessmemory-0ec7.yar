rule TTP_XOR_WriteProcessMemory_0ec7 {
  strings:
    $key_0ec7 = { 59 b5 [2] 6b 97 [2] 6d a2 [2] 43 a2 [2] 7c be }

  condition:
    any of them
}