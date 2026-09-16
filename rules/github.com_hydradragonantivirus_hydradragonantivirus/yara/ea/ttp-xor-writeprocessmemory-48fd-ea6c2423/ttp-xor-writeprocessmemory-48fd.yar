rule TTP_XOR_WriteProcessMemory_48fd {
  strings:
    $key_48fd = { 1f 8f [2] 2d ad [2] 2b 98 [2] 05 98 [2] 3a 84 }

  condition:
    any of them
}