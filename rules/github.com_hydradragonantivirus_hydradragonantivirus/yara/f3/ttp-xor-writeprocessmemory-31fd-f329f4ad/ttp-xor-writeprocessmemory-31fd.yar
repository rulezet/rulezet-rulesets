rule TTP_XOR_WriteProcessMemory_31fd {
  strings:
    $key_31fd = { 66 8f [2] 54 ad [2] 52 98 [2] 7c 98 [2] 43 84 }

  condition:
    any of them
}