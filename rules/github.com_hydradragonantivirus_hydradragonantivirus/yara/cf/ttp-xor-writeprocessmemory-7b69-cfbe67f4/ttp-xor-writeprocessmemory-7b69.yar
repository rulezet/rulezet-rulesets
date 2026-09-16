rule TTP_XOR_WriteProcessMemory_7b69 {
  strings:
    $key_7b69 = { 2c 1b [2] 1e 39 [2] 18 0c [2] 36 0c [2] 09 10 }

  condition:
    any of them
}