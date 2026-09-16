rule TTP_XOR_WriteProcessMemory_623c {
  strings:
    $key_623c = { 35 4e [2] 07 6c [2] 01 59 [2] 2f 59 [2] 10 45 }

  condition:
    any of them
}