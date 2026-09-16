rule TTP_XOR_WriteProcessMemory_6935 {
  strings:
    $key_6935 = { 3e 47 [2] 0c 65 [2] 0a 50 [2] 24 50 [2] 1b 4c }

  condition:
    any of them
}