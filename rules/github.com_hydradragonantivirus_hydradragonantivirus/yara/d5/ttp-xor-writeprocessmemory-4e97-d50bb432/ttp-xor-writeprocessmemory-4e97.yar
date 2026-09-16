rule TTP_XOR_WriteProcessMemory_4e97 {
  strings:
    $key_4e97 = { 19 e5 [2] 2b c7 [2] 2d f2 [2] 03 f2 [2] 3c ee }

  condition:
    any of them
}