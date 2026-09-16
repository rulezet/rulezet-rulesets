rule TTP_XOR_WriteProcessMemory_284c {
  strings:
    $key_284c = { 7f 3e [2] 4d 1c [2] 4b 29 [2] 65 29 [2] 5a 35 }

  condition:
    any of them
}