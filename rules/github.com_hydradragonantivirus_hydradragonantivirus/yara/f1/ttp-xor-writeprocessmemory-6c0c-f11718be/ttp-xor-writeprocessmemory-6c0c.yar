rule TTP_XOR_WriteProcessMemory_6c0c {
  strings:
    $key_6c0c = { 3b 7e [2] 09 5c [2] 0f 69 [2] 21 69 [2] 1e 75 }

  condition:
    any of them
}