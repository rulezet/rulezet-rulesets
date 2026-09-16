rule TTP_XOR_WriteProcessMemory_1ded {
  strings:
    $key_1ded = { 4a 9f [2] 78 bd [2] 7e 88 [2] 50 88 [2] 6f 94 }

  condition:
    any of them
}