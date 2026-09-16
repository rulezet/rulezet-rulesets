rule TTP_XOR_WriteProcessMemory_598c {
  strings:
    $key_598c = { 0e fe [2] 3c dc [2] 3a e9 [2] 14 e9 [2] 2b f5 }

  condition:
    any of them
}