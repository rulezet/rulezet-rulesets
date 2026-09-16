rule TTP_XOR_WriteProcessMemory_c9fa {
  strings:
    $key_c9fa = { 9e 88 [2] ac aa [2] aa 9f [2] 84 9f [2] bb 83 }

  condition:
    any of them
}