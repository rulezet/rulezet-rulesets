rule TTP_XOR_WriteProcessMemory_6e97 {
  strings:
    $key_6e97 = { 39 e5 [2] 0b c7 [2] 0d f2 [2] 23 f2 [2] 1c ee }

  condition:
    any of them
}