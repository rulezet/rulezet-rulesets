rule TTP_XOR_WriteProcessMemory_f8fd {
  strings:
    $key_f8fd = { af 8f [2] 9d ad [2] 9b 98 [2] b5 98 [2] 8a 84 }

  condition:
    any of them
}