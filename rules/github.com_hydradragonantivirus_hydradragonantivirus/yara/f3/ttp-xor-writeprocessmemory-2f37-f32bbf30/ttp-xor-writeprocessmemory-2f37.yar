rule TTP_XOR_WriteProcessMemory_2f37 {
  strings:
    $key_2f37 = { 78 45 [2] 4a 67 [2] 4c 52 [2] 62 52 [2] 5d 4e }

  condition:
    any of them
}