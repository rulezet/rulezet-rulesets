rule TTP_XOR_WriteProcessMemory_6917 {
  strings:
    $key_6917 = { 3e 65 [2] 0c 47 [2] 0a 72 [2] 24 72 [2] 1b 6e }

  condition:
    any of them
}