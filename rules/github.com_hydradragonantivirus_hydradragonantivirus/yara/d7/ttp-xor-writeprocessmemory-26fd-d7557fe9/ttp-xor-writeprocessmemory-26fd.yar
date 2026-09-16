rule TTP_XOR_WriteProcessMemory_26fd {
  strings:
    $key_26fd = { 71 8f [2] 43 ad [2] 45 98 [2] 6b 98 [2] 54 84 }

  condition:
    any of them
}