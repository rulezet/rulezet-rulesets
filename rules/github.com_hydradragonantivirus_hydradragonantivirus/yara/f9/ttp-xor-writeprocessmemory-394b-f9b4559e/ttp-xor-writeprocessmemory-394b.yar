rule TTP_XOR_WriteProcessMemory_394b {
  strings:
    $key_394b = { 6e 39 [2] 5c 1b [2] 5a 2e [2] 74 2e [2] 4b 32 }

  condition:
    any of them
}