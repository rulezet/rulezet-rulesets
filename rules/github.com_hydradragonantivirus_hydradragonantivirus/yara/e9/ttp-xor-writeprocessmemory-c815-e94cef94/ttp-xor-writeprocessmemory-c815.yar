rule TTP_XOR_WriteProcessMemory_c815 {
  strings:
    $key_c815 = { 9f 67 [2] ad 45 [2] ab 70 [2] 85 70 [2] ba 6c }

  condition:
    any of them
}