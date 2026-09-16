rule TTP_XOR_WriteProcessMemory_322b {
  strings:
    $key_322b = { 65 59 [2] 57 7b [2] 51 4e [2] 7f 4e [2] 40 52 }

  condition:
    any of them
}