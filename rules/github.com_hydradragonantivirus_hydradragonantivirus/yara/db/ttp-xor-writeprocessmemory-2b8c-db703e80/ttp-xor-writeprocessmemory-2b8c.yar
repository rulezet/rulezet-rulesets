rule TTP_XOR_WriteProcessMemory_2b8c {
  strings:
    $key_2b8c = { 7c fe [2] 4e dc [2] 48 e9 [2] 66 e9 [2] 59 f5 }

  condition:
    any of them
}