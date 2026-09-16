rule TTP_XOR_WriteProcessMemory_694d {
  strings:
    $key_694d = { 3e 3f [2] 0c 1d [2] 0a 28 [2] 24 28 [2] 1b 34 }

  condition:
    any of them
}