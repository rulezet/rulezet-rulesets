rule TTP_XOR_WriteProcessMemory_e63c {
  strings:
    $key_e63c = { b1 4e [2] 83 6c [2] 85 59 [2] ab 59 [2] 94 45 }

  condition:
    any of them
}