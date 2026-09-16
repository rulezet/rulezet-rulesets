rule TTP_XOR_WriteProcessMemory_06ed {
  strings:
    $key_06ed = { 51 9f [2] 63 bd [2] 65 88 [2] 4b 88 [2] 74 94 }

  condition:
    any of them
}