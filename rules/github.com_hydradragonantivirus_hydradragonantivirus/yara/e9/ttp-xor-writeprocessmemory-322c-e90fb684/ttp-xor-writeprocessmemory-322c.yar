rule TTP_XOR_WriteProcessMemory_322c {
  strings:
    $key_322c = { 65 5e [2] 57 7c [2] 51 49 [2] 7f 49 [2] 40 55 }

  condition:
    any of them
}