rule TTP_XOR_WriteProcessMemory_e8ed {
  strings:
    $key_e8ed = { bf 9f [2] 8d bd [2] 8b 88 [2] a5 88 [2] 9a 94 }

  condition:
    any of them
}