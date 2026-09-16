rule TTP_XOR_WriteProcessMemory_6901 {
  strings:
    $key_6901 = { 3e 73 [2] 0c 51 [2] 0a 64 [2] 24 64 [2] 1b 78 }

  condition:
    any of them
}