rule TTP_XOR_WriteProcessMemory_093b {
  strings:
    $key_093b = { 5e 49 [2] 6c 6b [2] 6a 5e [2] 44 5e [2] 7b 42 }

  condition:
    any of them
}