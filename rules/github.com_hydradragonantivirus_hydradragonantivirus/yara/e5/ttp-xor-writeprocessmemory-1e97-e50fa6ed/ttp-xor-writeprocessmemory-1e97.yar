rule TTP_XOR_WriteProcessMemory_1e97 {
  strings:
    $key_1e97 = { 49 e5 [2] 7b c7 [2] 7d f2 [2] 53 f2 [2] 6c ee }

  condition:
    any of them
}