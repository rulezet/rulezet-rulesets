rule TTP_XOR_WriteProcessMemory_3e3c {
  strings:
    $key_3e3c = { 69 4e [2] 5b 6c [2] 5d 59 [2] 73 59 [2] 4c 45 }

  condition:
    any of them
}