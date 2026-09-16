rule TTP_XOR_WriteProcessMemory_361c {
  strings:
    $key_361c = { 61 6e [2] 53 4c [2] 55 79 [2] 7b 79 [2] 44 65 }

  condition:
    any of them
}