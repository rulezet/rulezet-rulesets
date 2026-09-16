rule TTP_XOR_WriteProcessMemory_36fd {
  strings:
    $key_36fd = { 61 8f [2] 53 ad [2] 55 98 [2] 7b 98 [2] 44 84 }

  condition:
    any of them
}