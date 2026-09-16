rule TTP_XOR_WriteProcessMemory_2857 {
  strings:
    $key_2857 = { 7f 25 [2] 4d 07 [2] 4b 32 [2] 65 32 [2] 5a 2e }

  condition:
    any of them
}