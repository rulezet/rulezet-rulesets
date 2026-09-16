rule TTP_XOR_WriteProcessMemory_e3fd {
  strings:
    $key_e3fd = { b4 8f [2] 86 ad [2] 80 98 [2] ae 98 [2] 91 84 }

  condition:
    any of them
}