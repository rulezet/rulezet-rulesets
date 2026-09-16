rule TTP_XOR_WriteProcessMemory_22ea {
  strings:
    $key_22ea = { 75 98 [2] 47 ba [2] 41 8f [2] 6f 8f [2] 50 93 }

  condition:
    any of them
}