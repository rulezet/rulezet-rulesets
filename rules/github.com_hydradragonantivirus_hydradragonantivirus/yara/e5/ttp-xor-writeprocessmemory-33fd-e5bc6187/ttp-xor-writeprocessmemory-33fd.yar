rule TTP_XOR_WriteProcessMemory_33fd {
  strings:
    $key_33fd = { 64 8f [2] 56 ad [2] 50 98 [2] 7e 98 [2] 41 84 }

  condition:
    any of them
}