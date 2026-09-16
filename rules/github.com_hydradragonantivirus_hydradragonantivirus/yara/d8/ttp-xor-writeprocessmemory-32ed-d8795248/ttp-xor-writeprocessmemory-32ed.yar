rule TTP_XOR_WriteProcessMemory_32ed {
  strings:
    $key_32ed = { 65 9f [2] 57 bd [2] 51 88 [2] 7f 88 [2] 40 94 }

  condition:
    any of them
}