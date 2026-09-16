rule TTP_XOR_WriteProcessMemory_5c39 {
  strings:
    $key_5c39 = { 0b 4b [2] 39 69 [2] 3f 5c [2] 11 5c [2] 2e 40 }

  condition:
    any of them
}