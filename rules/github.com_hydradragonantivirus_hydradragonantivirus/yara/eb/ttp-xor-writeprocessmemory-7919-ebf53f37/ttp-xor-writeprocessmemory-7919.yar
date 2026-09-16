rule TTP_XOR_WriteProcessMemory_7919 {
  strings:
    $key_7919 = { 2e 6b [2] 1c 49 [2] 1a 7c [2] 34 7c [2] 0b 60 }

  condition:
    any of them
}