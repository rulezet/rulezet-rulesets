rule TTP_XOR_WriteProcessMemory_095d {
  strings:
    $key_095d = { 5e 2f [2] 6c 0d [2] 6a 38 [2] 44 38 [2] 7b 24 }

  condition:
    any of them
}