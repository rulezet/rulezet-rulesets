rule TTP_XOR_WriteProcessMemory_091d {
  strings:
    $key_091d = { 5e 6f [2] 6c 4d [2] 6a 78 [2] 44 78 [2] 7b 64 }

  condition:
    any of them
}