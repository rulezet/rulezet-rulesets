rule TTP_XOR_WriteProcessMemory_7969 {
  strings:
    $key_7969 = { 2e 1b [2] 1c 39 [2] 1a 0c [2] 34 0c [2] 0b 10 }

  condition:
    any of them
}