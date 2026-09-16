rule TTP_XOR_WriteProcessMemory_322d {
  strings:
    $key_322d = { 65 5f [2] 57 7d [2] 51 48 [2] 7f 48 [2] 40 54 }

  condition:
    any of them
}