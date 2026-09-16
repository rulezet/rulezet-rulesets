rule TTP_XOR_WriteProcessMemory_065c {
  strings:
    $key_065c = { 51 2e [2] 63 0c [2] 65 39 [2] 4b 39 [2] 74 25 }

  condition:
    any of them
}