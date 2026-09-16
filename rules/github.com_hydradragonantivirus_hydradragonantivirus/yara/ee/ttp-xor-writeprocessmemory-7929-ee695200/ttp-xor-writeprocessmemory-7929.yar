rule TTP_XOR_WriteProcessMemory_7929 {
  strings:
    $key_7929 = { 2e 5b [2] 1c 79 [2] 1a 4c [2] 34 4c [2] 0b 50 }

  condition:
    any of them
}