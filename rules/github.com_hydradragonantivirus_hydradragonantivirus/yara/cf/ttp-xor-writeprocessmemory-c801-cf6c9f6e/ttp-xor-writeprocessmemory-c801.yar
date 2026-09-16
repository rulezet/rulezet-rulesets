rule TTP_XOR_WriteProcessMemory_c801 {
  strings:
    $key_c801 = { 9f 73 [2] ad 51 [2] ab 64 [2] 85 64 [2] ba 78 }

  condition:
    any of them
}