rule TTP_XOR_WriteProcessMemory_0d01 {
  strings:
    $key_0d01 = { 5a 73 [2] 68 51 [2] 6e 64 [2] 40 64 [2] 7f 78 }

  condition:
    any of them
}