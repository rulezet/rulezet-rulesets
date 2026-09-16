rule TTP_XOR_WriteProcessMemory_2e61 {
  strings:
    $key_2e61 = { 79 13 [2] 4b 31 [2] 4d 04 [2] 63 04 [2] 5c 18 }

  condition:
    any of them
}