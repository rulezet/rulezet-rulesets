rule TTP_XOR_WriteProcessMemory_5ded {
  strings:
    $key_5ded = { 0a 9f [2] 38 bd [2] 3e 88 [2] 10 88 [2] 2f 94 }

  condition:
    any of them
}