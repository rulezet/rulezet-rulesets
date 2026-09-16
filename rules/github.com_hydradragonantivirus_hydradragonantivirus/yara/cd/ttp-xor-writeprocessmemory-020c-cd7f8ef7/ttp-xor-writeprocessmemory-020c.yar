rule TTP_XOR_WriteProcessMemory_020c {
  strings:
    $key_020c = { 55 7e [2] 67 5c [2] 61 69 [2] 4f 69 [2] 70 75 }

  condition:
    any of them
}