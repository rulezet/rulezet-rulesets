rule TTP_XOR_WriteProcessMemory_6ccd {
  strings:
    $key_6ccd = { 3b bf [2] 09 9d [2] 0f a8 [2] 21 a8 [2] 1e b4 }

  condition:
    any of them
}