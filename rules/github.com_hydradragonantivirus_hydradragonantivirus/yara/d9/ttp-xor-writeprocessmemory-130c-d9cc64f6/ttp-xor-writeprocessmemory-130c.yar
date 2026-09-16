rule TTP_XOR_WriteProcessMemory_130c {
  strings:
    $key_130c = { 44 7e [2] 76 5c [2] 70 69 [2] 5e 69 [2] 61 75 }

  condition:
    any of them
}