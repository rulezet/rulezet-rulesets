rule TTP_XOR_WriteProcessMemory_18fd {
  strings:
    $key_18fd = { 4f 8f [2] 7d ad [2] 7b 98 [2] 55 98 [2] 6a 84 }

  condition:
    any of them
}