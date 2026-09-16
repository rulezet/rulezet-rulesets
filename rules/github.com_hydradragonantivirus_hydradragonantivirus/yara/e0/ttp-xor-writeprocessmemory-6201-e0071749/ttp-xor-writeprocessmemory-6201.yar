rule TTP_XOR_WriteProcessMemory_6201 {
  strings:
    $key_6201 = { 35 73 [2] 07 51 [2] 01 64 [2] 2f 64 [2] 10 78 }

  condition:
    any of them
}