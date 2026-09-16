rule TTP_XOR_WriteProcessMemory_3931 {
  strings:
    $key_3931 = { 6e 43 [2] 5c 61 [2] 5a 54 [2] 74 54 [2] 4b 48 }

  condition:
    any of them
}