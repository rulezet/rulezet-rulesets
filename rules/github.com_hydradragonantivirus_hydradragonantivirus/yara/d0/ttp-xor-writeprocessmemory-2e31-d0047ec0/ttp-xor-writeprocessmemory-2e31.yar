rule TTP_XOR_WriteProcessMemory_2e31 {
  strings:
    $key_2e31 = { 79 43 [2] 4b 61 [2] 4d 54 [2] 63 54 [2] 5c 48 }

  condition:
    any of them
}