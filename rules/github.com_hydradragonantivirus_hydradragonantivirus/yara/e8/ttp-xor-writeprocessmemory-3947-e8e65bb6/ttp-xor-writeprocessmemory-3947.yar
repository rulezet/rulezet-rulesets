rule TTP_XOR_WriteProcessMemory_3947 {
  strings:
    $key_3947 = { 6e 35 [2] 5c 17 [2] 5a 22 [2] 74 22 [2] 4b 3e }

  condition:
    any of them
}