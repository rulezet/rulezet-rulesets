rule TTP_XOR_WriteProcessMemory_198c {
  strings:
    $key_198c = { 4e fe [2] 7c dc [2] 7a e9 [2] 54 e9 [2] 6b f5 }

  condition:
    any of them
}