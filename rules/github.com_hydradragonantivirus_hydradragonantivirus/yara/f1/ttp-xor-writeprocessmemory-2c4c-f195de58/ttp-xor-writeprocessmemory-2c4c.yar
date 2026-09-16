rule TTP_XOR_WriteProcessMemory_2c4c {
  strings:
    $key_2c4c = { 7b 3e [2] 49 1c [2] 4f 29 [2] 61 29 [2] 5e 35 }

  condition:
    any of them
}