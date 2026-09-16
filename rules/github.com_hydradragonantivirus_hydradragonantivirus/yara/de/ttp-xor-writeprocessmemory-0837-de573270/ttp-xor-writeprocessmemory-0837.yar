rule TTP_XOR_WriteProcessMemory_0837 {
  strings:
    $key_0837 = { 5f 45 [2] 6d 67 [2] 6b 52 [2] 45 52 [2] 7a 4e }

  condition:
    any of them
}