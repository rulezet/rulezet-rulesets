rule TTP_XOR_WriteProcessMemory_78ed {
  strings:
    $key_78ed = { 2f 9f [2] 1d bd [2] 1b 88 [2] 35 88 [2] 0a 94 }

  condition:
    any of them
}