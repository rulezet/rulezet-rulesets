rule TTP_XOR_WriteProcessMemory_78fd {
  strings:
    $key_78fd = { 2f 8f [2] 1d ad [2] 1b 98 [2] 35 98 [2] 0a 84 }

  condition:
    any of them
}