rule TTP_XOR_WriteProcessMemory_73e8 {
  strings:
    $key_73e8 = { 24 9a [2] 16 b8 [2] 10 8d [2] 3e 8d [2] 01 91 }

  condition:
    any of them
}