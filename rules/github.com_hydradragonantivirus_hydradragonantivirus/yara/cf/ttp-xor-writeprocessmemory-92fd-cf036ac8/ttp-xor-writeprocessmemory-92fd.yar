rule TTP_XOR_WriteProcessMemory_92fd {
  strings:
    $key_92fd = { c5 8f [2] f7 ad [2] f1 98 [2] df 98 [2] e0 84 }

  condition:
    any of them
}