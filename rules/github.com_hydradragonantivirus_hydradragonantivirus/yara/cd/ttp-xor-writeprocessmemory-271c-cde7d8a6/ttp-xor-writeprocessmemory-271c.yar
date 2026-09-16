rule TTP_XOR_WriteProcessMemory_271c {
  strings:
    $key_271c = { 70 6e [2] 42 4c [2] 44 79 [2] 6a 79 [2] 55 65 }

  condition:
    any of them
}