rule TTP_XOR_WriteProcessMemory_5617 {
  strings:
    $key_5617 = { 01 65 [2] 33 47 [2] 35 72 [2] 1b 72 [2] 24 6e }

  condition:
    any of them
}