rule TTP_XOR_WriteProcessMemory_2826 {
  strings:
    $key_2826 = { 7f 54 [2] 4d 76 [2] 4b 43 [2] 65 43 [2] 5a 5f }

  condition:
    any of them
}