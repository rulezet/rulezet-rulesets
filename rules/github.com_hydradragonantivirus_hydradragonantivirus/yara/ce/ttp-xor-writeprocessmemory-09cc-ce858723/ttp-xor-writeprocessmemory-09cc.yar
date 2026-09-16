rule TTP_XOR_WriteProcessMemory_09cc {
  strings:
    $key_09cc = { 5e be [2] 6c 9c [2] 6a a9 [2] 44 a9 [2] 7b b5 }

  condition:
    any of them
}