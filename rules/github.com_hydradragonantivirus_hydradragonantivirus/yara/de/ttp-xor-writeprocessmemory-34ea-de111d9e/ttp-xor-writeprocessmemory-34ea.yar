rule TTP_XOR_WriteProcessMemory_34ea {
  strings:
    $key_34ea = { 63 98 [2] 51 ba [2] 57 8f [2] 79 8f [2] 46 93 }

  condition:
    any of them
}