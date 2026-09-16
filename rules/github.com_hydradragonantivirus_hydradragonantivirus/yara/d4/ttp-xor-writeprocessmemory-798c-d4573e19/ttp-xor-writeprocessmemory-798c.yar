rule TTP_XOR_WriteProcessMemory_798c {
  strings:
    $key_798c = { 2e fe [2] 1c dc [2] 1a e9 [2] 34 e9 [2] 0b f5 }

  condition:
    any of them
}