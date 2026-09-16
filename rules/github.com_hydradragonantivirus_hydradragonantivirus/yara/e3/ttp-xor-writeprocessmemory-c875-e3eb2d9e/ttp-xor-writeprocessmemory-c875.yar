rule TTP_XOR_WriteProcessMemory_c875 {
  strings:
    $key_c875 = { 9f 07 [2] ad 25 [2] ab 10 [2] 85 10 [2] ba 0c }

  condition:
    any of them
}