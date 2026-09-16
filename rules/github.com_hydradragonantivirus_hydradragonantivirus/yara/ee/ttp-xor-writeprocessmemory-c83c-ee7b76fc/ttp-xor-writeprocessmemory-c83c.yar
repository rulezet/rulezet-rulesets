rule TTP_XOR_WriteProcessMemory_c83c {
  strings:
    $key_c83c = { 9f 4e [2] ad 6c [2] ab 59 [2] 85 59 [2] ba 45 }

  condition:
    any of them
}