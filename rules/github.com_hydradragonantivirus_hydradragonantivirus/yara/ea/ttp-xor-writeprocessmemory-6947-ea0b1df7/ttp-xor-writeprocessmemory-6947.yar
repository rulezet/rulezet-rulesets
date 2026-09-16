rule TTP_XOR_WriteProcessMemory_6947 {
  strings:
    $key_6947 = { 3e 35 [2] 0c 17 [2] 0a 22 [2] 24 22 [2] 1b 3e }

  condition:
    any of them
}