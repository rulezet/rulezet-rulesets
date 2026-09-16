rule TTP_XOR_WriteProcessMemory_e935 {
  strings:
    $key_e935 = { be 47 [2] 8c 65 [2] 8a 50 [2] a4 50 [2] 9b 4c }

  condition:
    any of them
}