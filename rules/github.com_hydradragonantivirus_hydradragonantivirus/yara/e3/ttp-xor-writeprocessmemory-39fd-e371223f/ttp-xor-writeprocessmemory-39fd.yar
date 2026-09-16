rule TTP_XOR_WriteProcessMemory_39fd {
  strings:
    $key_39fd = { 6e 8f [2] 5c ad [2] 5a 98 [2] 74 98 [2] 4b 84 }

  condition:
    any of them
}