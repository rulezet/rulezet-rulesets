rule TTP_XOR_WriteProcessMemory_2846 {
  strings:
    $key_2846 = { 7f 34 [2] 4d 16 [2] 4b 23 [2] 65 23 [2] 5a 3f }

  condition:
    any of them
}