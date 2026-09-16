rule TTP_XOR_WriteProcessMemory_298c {
  strings:
    $key_298c = { 7e fe [2] 4c dc [2] 4a e9 [2] 64 e9 [2] 5b f5 }

  condition:
    any of them
}