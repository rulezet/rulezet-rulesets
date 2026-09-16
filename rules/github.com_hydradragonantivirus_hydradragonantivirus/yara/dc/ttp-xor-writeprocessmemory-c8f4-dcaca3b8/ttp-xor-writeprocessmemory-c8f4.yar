rule TTP_XOR_WriteProcessMemory_c8f4 {
  strings:
    $key_c8f4 = { 9f 86 [2] ad a4 [2] ab 91 [2] 85 91 [2] ba 8d }

  condition:
    any of them
}