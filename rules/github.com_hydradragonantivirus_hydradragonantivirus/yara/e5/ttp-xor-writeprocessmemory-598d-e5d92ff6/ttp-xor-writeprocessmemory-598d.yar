rule TTP_XOR_WriteProcessMemory_598d {
  strings:
    $key_598d = { 0e ff [2] 3c dd [2] 3a e8 [2] 14 e8 [2] 2b f4 }

  condition:
    any of them
}