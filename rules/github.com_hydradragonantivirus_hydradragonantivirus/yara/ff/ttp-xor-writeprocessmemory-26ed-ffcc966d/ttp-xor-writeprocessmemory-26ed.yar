rule TTP_XOR_WriteProcessMemory_26ed {
  strings:
    $key_26ed = { 71 9f [2] 43 bd [2] 45 88 [2] 6b 88 [2] 54 94 }

  condition:
    any of them
}